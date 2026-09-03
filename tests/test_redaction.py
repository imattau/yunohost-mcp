from __future__ import annotations

from yunohost_mcp.redaction import is_sensitive_key, redact, redact_response, redact_text


def test_is_sensitive_key_matches_known_markers():
    for key in ["password", "db_password", "ldap_password", "api_key", "apiKey", "SECRET", "nsec", "session_id", "cookie"]:
        assert is_sensitive_key(key), key


def test_is_sensitive_key_does_not_match_unrelated_keys():
    for key in ["username", "app", "domain", "description", "id", "version"]:
        assert not is_sensitive_key(key), key


def test_redact_flat_dict():
    result = redact({"username": "alice", "password": "hunter2"})
    assert result == {"username": "alice", "password": "[REDACTED]"}


def test_redact_nested_dict():
    result = redact({"settings": {"domain": "example.com", "db_password": "s3cr3t"}})
    assert result == {"settings": {"domain": "example.com", "db_password": "[REDACTED]"}}


def test_redact_list_of_dicts():
    result = redact([{"token": "abc"}, {"name": "ok"}])
    assert result == [{"token": "[REDACTED]"}, {"name": "ok"}]


def test_redact_leaves_non_containers_alone():
    assert redact("hello") == "hello"
    assert redact(42) == 42
    assert redact(None) is None


def test_redact_does_not_mutate_original():
    original = {"password": "hunter2"}
    redact(original)
    assert original == {"password": "hunter2"}


def test_redact_response_decorator_redacts_dict_return_value():
    @redact_response
    def fn():
        return {"username": "alice", "password": "hunter2"}

    assert fn() == {"username": "alice", "password": "[REDACTED]"}


def test_redact_response_decorator_passes_through_non_dict():
    @redact_response
    def fn():
        return "plain string"

    assert fn() == "plain string"


def test_redact_response_decorator_preserves_args_and_kwargs():
    @redact_response
    def fn(a, b, *, c):
        return {"a": a, "b": b, "c": c}

    assert fn(1, 2, c=3) == {"a": 1, "b": 2, "c": 3}


def test_redact_text_redacts_shell_style_kv_assignments():
    # Exactly the shape a real operation log's shell trace produces -
    # redact()'s key-based pass can never reach this, since the *line*'s
    # own dict key is "logs"/"message", not anything sensitive-sounding.
    assert redact_text("+ export DB_PASSWORD=hunter2") == "+ export DB_PASSWORD=[REDACTED]"
    assert redact_text("api_key: sk-abc123xyz") == "api_key: [REDACTED]"
    assert redact_text("Authorization=Bearer abc.def.ghi") == "Authorization=[REDACTED]"


def test_redact_text_redacts_bare_nsec_keys():
    line = "signing as nsec1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqycz3aj"
    result = redact_text(line)
    assert "nsec1" not in result
    assert "[REDACTED]" in result


def test_redact_text_leaves_ordinary_paths_urls_and_commands_intact():
    # The whole point of these tools is diagnosing real bugs from this
    # exact detail - only secret-*shaped* content should ever be touched.
    line = "+ curl https://github.com/imattau/yunohost-mcp/releases/download/v0.1.13/x.tar.gz -o /tmp/x.tar.gz"
    assert redact_text(line) == line


def test_redact_text_leaves_unrelated_kv_pairs_intact():
    assert redact_text("domain=example.com path=/site") == "domain=example.com path=/site"
