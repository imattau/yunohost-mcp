"""Root-side Unix socket helper for the typed privileged broker."""

from __future__ import annotations

import argparse
import logging
import os
import pwd
import socket
import socketserver
import stat
import struct
import time
from pathlib import Path

from yunohost_mcp.broker.operations import OPERATIONS
from yunohost_mcp.broker.protocol import BrokerProtocolError, decode_original_body, decode_request, encode_response
from yunohost_mcp.auth.groups import identity_store_for_settings
from yunohost_mcp.auth.middleware import NostrAuthMiddleware
from yunohost_mcp.auth.nip98 import Nip98Error, verify_nip98_request
from yunohost_mcp.auth.replay import ReplayCache
from yunohost_mcp.auth.revocation import RevocationStore
from yunohost_mcp.auth.server_identity import ServerIdentity
from yunohost_mcp.audit.log import AuditLog
from yunohost_mcp.config import Settings
from yunohost_mcp.policy.scopes import Scope
from yunohost_mcp.policy.confirmation import SQLiteConfirmationStore
from yunohost_mcp.policy.confirmation import ConfirmationError
from yunohost_mcp.policy.rules import check_free_space, check_recent_backup, load_policy
from yunohost_mcp.yunohost.adapter import YunohostAdapter, YunohostUnavailableError

logger = logging.getLogger("yunohost_mcp.broker")
_UCRED_FORMAT = "3i"


def peer_uid(conn: socket.socket) -> int:
    data = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize(_UCRED_FORMAT))
    _pid, uid, _gid = struct.unpack(_UCRED_FORMAT, data)
    return uid


class BrokerServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, socket_path: Path, allowed_uid: int, adapter: YunohostAdapter | None = None):
        self.allowed_uid = allowed_uid
        # The root helper must never recursively call another broker even if
        # the service environment contains YUNOHOST_MCP_BROKER_SOCKET_PATH.
        self.settings = Settings(broker_socket_path=None)
        self.adapter = adapter or YunohostAdapter(self.settings)
        self.identity_store = identity_store_for_settings(self.settings)
        self.replay_cache = ReplayCache(ttl_seconds=self.settings.nip98_replay_ttl_seconds)
        self.server_identity = ServerIdentity.load_or_generate(self.settings.server_identity_path())
        self.revocation_store = RevocationStore.live(self.settings.revoked_delegations_path())
        self.confirmation_store = (
            SQLiteConfirmationStore(
                self.settings.confirmation_store_file,
                ttl_seconds=self.settings.confirmation_ttl_seconds,
                owner_approval_ttl_seconds=self.settings.owner_approval_ttl_seconds,
            )
            if self.settings.confirmation_store_file
            else None
        )
        self.policy_rules = load_policy(self.settings.policy_file_path())
        self.audit_log = AuditLog(path=self.settings.audit_log_path())
        super().__init__(str(socket_path), BrokerRequestHandler)


class BrokerRequestHandler(socketserver.StreamRequestHandler):
    server: BrokerServer

    def handle(self) -> None:
        request_id = "unknown"
        operation_name = "unknown"
        caller_pubkey = "unknown"
        audit_decision = "denied"
        audit_result = "error"
        audit_error = None
        audit_operation_id = None
        try:
            if peer_uid(self.request) != self.server.allowed_uid:
                self._send(request_id, ok=False, error="forbidden peer")
                return
            line = self.rfile.readline(1_048_577)
            request = decode_request(line.rstrip(b"\n"))
            request_id = request.request_id
            operation_name = request.operation
            operation = OPERATIONS.get(request.operation)
            if operation is None:
                raise BrokerProtocolError("unsupported operation")
            identity = authorize_request(request, self.server)
            caller_pubkey = identity.pubkey
            required = Scope(operation.required_scope)
            if not identity.has_scope(required):
                raise BrokerProtocolError("caller lacks the required operation scope")
            confirmation_id = self._check_operation_policy(request, operation.name, identity)
            audit_decision = "allowed"
            result = operation.invoke(self.server.adapter, request.arguments)
            if confirmation_id is not None:
                self.server.confirmation_store.finalize(confirmation_id)
            audit_result = "success"
            if isinstance(result, dict):
                audit_operation_id = result.get("operation_id")
            self._send(request_id, ok=True, result=result)
        except (BrokerProtocolError, ValueError) as exc:
            audit_error = str(exc)
            self._send(request_id, ok=False, error=str(exc))
        except YunohostUnavailableError as exc:
            # Preserve expected YunoHost/runtime failures at the broker
            # boundary. Masking these as "internal broker error" makes a
            # missing dependency or LDAP/runtime problem impossible to
            # diagnose from an MCP client.
            audit_error = str(exc)
            self._send(request_id, ok=False, error=str(exc))
        except Exception:
            logger.exception("unexpected broker failure for request %s", request_id)
            audit_error = "internal broker error"
            self._send(request_id, ok=False, error="internal broker error")
        finally:
            try:
                self.server.audit_log.record(
                    tool=operation_name,
                    arguments=(request.arguments if "request" in locals() else {}),
                    caller_pubkey=caller_pubkey,
                    decision=audit_decision,
                    result=audit_result,
                    yunohost_operation=audit_operation_id,
                    error=audit_error,
                    request_id=request_id if request_id != "unknown" else None,
                    execution_context="broker",
                )
            except Exception:
                logger.exception("could not write broker audit entry for request %s", request_id)

    def _send(self, request_id: str, *, ok: bool, result=None, error: str | None = None) -> None:
        self.request.sendall(encode_response(request_id=request_id, ok=ok, result=result, error=error))

    def _check_operation_policy(self, request, operation_name: str, identity) -> str | None:
        """Re-apply hard policy and confirmation at the root boundary.

        The frontend's authorization response is intentionally not trusted
        here.  The helper owns the final check immediately before invoking
        the root-side adapter.
        """
        policy_name = {
            "app.upgrade": "apps.upgrade",
            "app.remove": "apps.remove",
            "app.change_url": "apps.change_url",
            "app.config_set": "apps.config",
            "backup.restore": "backups.restore",
            "system.upgrade": "system.upgrade",
            "migrations.run": "system.migrate",
            "firewall.open": "firewall.write",
            "firewall.close": "firewall.write",
            "firewall.reload": "firewall.write",
            "user.create": "users.write",
            "user.update": "users.write",
            "user.delete": "users.delete",
            "user.group_create": "users.write",
            "user.group_update": "users.write",
            "user.group_delete": "users.delete",
            "user.permission_add": "users.permissions",
            "user.permission_remove": "users.permissions",
            "domain.add": "domains.write",
            "domain.cert_install": "domains.cert",
            "app.install": "apps.install",
            "backup.create": "backups.create",
            "service.restart": "services.restart",
            "catalog.publish": "catalog.publish",
            "package.run_tests": "packages.test",
            "safe.upgrade": "apps.upgrade",
        }.get(operation_name)
        if policy_name is None:
            return None
        rule = self.server.policy_rules.get(policy_name)
        if rule is None:
            return None
        check_free_space(rule, free_bytes=self.server.adapter.free_space_bytes())
        # safe_upgrade creates its own fresh safety backup inside the
        # workflow, so its preflight only checks the hard free-space floor;
        # the normal app.upgrade path still requires a pre-existing backup.
        if operation_name != "safe.upgrade":
            check_recent_backup(
                rule,
                archive_created_at=self.server.adapter.backup_created_at_times(),
                now=time.time(),
            )
        if not rule.require_confirmation:
            return None
        confirmation_id = request.arguments.get("confirmation_id")
        if not isinstance(confirmation_id, str) or not self.server.confirmation_store:
            raise BrokerProtocolError("confirmation is required for this operation")
        argument_keys = {
            "app.upgrade": ("app", "force", "url"),
            "app.remove": ("app", "purge"),
            "app.change_url": ("app", "domain", "path"),
            "app.config_set": ("app", "key", "value"),
            "backup.restore": ("name", "apps", "system", "force"),
            "system.upgrade": (),
            "migrations.run": (
                "targets", "skip", "auto", "force_rerun", "accept_disclaimer", "skip_postmigrations"
            ),
            "firewall.open": ("port", "protocol", "comment", "upnp", "no_reload"),
            "firewall.close": ("port", "protocol", "upnp_only", "no_reload"),
            "firewall.reload": ("skip_upnp",),
            "user.create": ("username", "domain", "password", "fullname", "mailbox_quota", "admin"),
            "user.update": (
                "username", "mail", "change_password", "add_mailforward", "remove_mailforward",
                "add_mailalias", "remove_mailalias", "mailbox_quota", "fullname",
            ),
            "user.delete": ("username", "purge"),
            "user.group_create": ("groupname",),
            "user.group_update": ("groupname", "add", "remove"),
            "user.group_delete": ("groupname",),
            "user.permission_add": ("permission", "names"),
            "user.permission_remove": ("permission", "names"),
            "domain.add": ("domain", "install_letsencrypt_cert"),
            "domain.cert_install": ("domain", "letsencrypt", "staging"),
            "app.install": ("app", "label", "args", "force"),
            "backup.create": ("name", "description", "apps", "system"),
            "service.restart": ("names",),
            "catalog.publish": ("plan_id",),
            "package.run_tests": ("source", "app_id"),
        }.get(operation_name)
        if argument_keys is None:
            raise BrokerProtocolError(f"no confirmation argument binding for {operation_name!r}")
        confirmation_arguments = {key: request.arguments.get(key) for key in argument_keys}
        try:
            self.server.confirmation_store.consume(
                confirmation_id,
                pubkey=identity.pubkey,
                tool=policy_name,
                arguments=confirmation_arguments,
                require_owner_approval=rule.require_owner_signature,
                defer=True,
            )
        except ConfirmationError as exc:
            raise BrokerProtocolError(f"invalid confirmation: {exc}") from exc
        return confirmation_id


def authorize_request(request, server: BrokerServer):
    """Independently authenticate a request at the root boundary.

    The helper verifies the original external request, not the Unix-socket
    transport.  This function intentionally has no frontend-provided
    ``authorized`` flag or scope list to trust.
    """
    if not request.authorization or not request.method or not request.url:
        raise BrokerProtocolError("complete original request authentication is required")
    body = decode_original_body(request)
    try:
        authenticated = verify_nip98_request(
            authorization_header=request.authorization,
            method=request.method,
            url=request.url,
            body=body,
            replay_cache=server.replay_cache,
        )
    except Nip98Error as exc:
        raise BrokerProtocolError(f"NIP-98 authentication failed: {exc}") from exc

    # Reuse the already-tested delegation resolution semantics, but execute
    # them inside the root process against its own live configuration.
    middleware = NostrAuthMiddleware(
        None,
        identity_store=server.identity_store,
        server_identity=server.server_identity,
        revocation_store=server.revocation_store,
    )
    headers = {}
    if request.delegation:
        headers["x-nostr-delegation"] = request.delegation
    record = middleware._resolve_identity(authenticated.pubkey, headers)  # noqa: SLF001
    if record is None:
        raise BrokerProtocolError("pubkey is not authorized")
    from yunohost_mcp.auth.identity import AuthenticatedRequest

    return AuthenticatedRequest(
        pubkey=authenticated.pubkey,
        event_id=authenticated.event_id,
        event_created_at=authenticated.created_at,
        identity=record,
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="YunoHost MCP privileged broker")
    parser.add_argument("--socket-path", type=Path, required=True)
    parser.add_argument("--allowed-user", required=True)
    args = parser.parse_args(argv)
    allowed_uid = pwd.getpwnam(args.allowed_user).pw_uid
    args.socket_path.parent.mkdir(parents=True, exist_ok=True)
    if args.socket_path.exists() or args.socket_path.is_symlink():
        if not stat.S_ISSOCK(args.socket_path.stat().st_mode):
            raise SystemExit(f"refusing to replace non-socket path: {args.socket_path}")
        args.socket_path.unlink()
    server = BrokerServer(args.socket_path, allowed_uid)
    # YunoHost's LDAPInterface authenticates the root connection through
    # SASL-EXTERNAL and verifies the complete peer identity, including the
    # effective GID (gidNumber=0+uidNumber=0).  The packaged systemd unit
    # therefore runs this process with root's primary group.  Keep the
    # socket narrowly accessible by changing only the socket's group to the
    # unprivileged frontend user's primary group after binding it.
    allowed_gid = pwd.getpwnam(args.allowed_user).pw_gid
    os.chown(args.socket_path, 0, allowed_gid)
    args.socket_path.chmod(0o660)
    logger.info("broker listening on %s", args.socket_path)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        args.socket_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
