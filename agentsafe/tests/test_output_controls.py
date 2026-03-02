from agentsafe.policy.output_controls import cap_text_bytes, deterministic_jitter_ms


def test_cap_text_bytes_truncates():
    text = "hello-world"
    capped, truncated = cap_text_bytes(text, 5)
    assert capped == "hello"
    assert truncated is True


def test_cap_text_bytes_no_truncate():
    capped, truncated = cap_text_bytes("ok", 10)
    assert capped == "ok"
    assert truncated is False


def test_deterministic_jitter_is_stable():
    j1 = deterministic_jitter_ms("req-1", 50)
    j2 = deterministic_jitter_ms("req-1", 50)
    assert j1 == j2
    assert 0 <= j1 <= 50
