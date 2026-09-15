from parser import parse_log_line

def test_parse_valid_log_line():
    line = "2026-09-14 09:31:22 | 192.168.1.10 | LOGIN_SUCCESS | vasileios"

    result = parse_log_line(line)

    assert result is not None
    assert result["ip"] == "192.168.1.10"
    assert result["event"] == "LOGIN_SUCCESS"
    assert result["username"] == "vasileios"

def test_parse_malformed_log_line():
    line = "this is not a valid log line"

    result = parse_log_line(line)

    assert result is None

def test_parse_invalid_timestamp():
    line = "2026-99-99 99:99:99 | 192.168.1.20 | LOGIN_FAILED | testuser"

    result = parse_log_line(line)

    assert result is None