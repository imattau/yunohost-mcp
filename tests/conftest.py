"""Test-wide setup, loaded before any test module.

yunohost_mcp.server reads Settings (env-driven) at import time and Phase 5's
write tools touch settings.audit_log_path() on every call - default to
/etc/yunohost-mcp, which this sandbox can't write to. Point it somewhere
writable before any test imports yunohost_mcp.server.
"""

import os
import tempfile

os.environ.setdefault("YUNOHOST_MCP_CONFIG_DIR", tempfile.mkdtemp(prefix="yunohost-mcp-test-"))
# Tests run on hosts without YunoHost installed; fake mode is an explicit
# test fixture now that production correctly defaults to real mode.
os.environ.setdefault("YUNOHOST_MCP_FAKE_YUNOHOST", "true")
os.environ.setdefault("YUNOHOST_MCP_CATALOG_RELAYS", "wss://relay.test")
