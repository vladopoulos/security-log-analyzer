from datetime import datetime
from analyzer import detect_brute_force, detect_multiple_ip_attack

def test_detect_brute_force():
    timestamps = [
        datetime(2026, 9, 14, 9, 31, 35),
        datetime(2026, 9, 14, 9, 31, 37),
        datetime(2026, 9, 14, 9, 31, 39),
    ]

    assert detect_brute_force(timestamps) is True

def test_no_brute_force_when_attempts_are_spread_out():
    timestamps = [
        datetime(2026, 9, 14, 9, 31, 35),
        datetime(2026, 9, 14, 10, 31, 37),
        datetime(2026, 9, 14, 11, 31, 39),
    ]

    assert detect_brute_force(timestamps) is False

def test_detect_multiple_ip_attack():
    ips = {
        "192.168.1.42",
        "10.0.0.50",
        "10.0.0.51"
    }

    assert detect_multiple_ip_attack(ips) is True

def test_no_multiple_ip_attack_below_threshold():
    ips = {
        "192.168.1.42",
        "10.0.0.50"
    }

    assert detect_multiple_ip_attack(ips) is False