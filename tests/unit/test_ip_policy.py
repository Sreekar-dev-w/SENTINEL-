import pytest

from app.security.ip_policy import (
    UnsafeIPAddress,
    assess_ip,
    unsafe_reason,
    validate_ip,
    validate_ip_addresses,
)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "::1",
        "10.10.10.10",
        "192.168.1.10",
        "169.254.1.1",
        "169.254.169.254",
        "169.254.170.2",
        "fd00:ec2::254",
        "ff02::1",
        "0.0.0.0",
        "2001:db8::1",
        "::ffff:127.0.0.1",
    ],
)
def test_rejects_unsafe_ipv4_ipv6_and_metadata_destinations(value):
    with pytest.raises(UnsafeIPAddress):
        validate_ip(value)


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "2001:4860:4860::8888",
    ],
)
def test_accepts_global_ipv4_and_ipv6_destinations(value):
    assert validate_ip(value) == value.lower()
    assert unsafe_reason(value) is None


def test_assessment_reports_reason_without_throwing_for_unsafe_address():
    assessment = assess_ip("192.168.0.1")

    assert assessment.safe is False
    assert assessment.reason == "private address"


def test_assessment_reports_invalid_input():
    assessment = assess_ip("not-an-ip")

    assert assessment.safe is False
    assert "invalid IP address" in assessment.reason


def test_rejects_ipv6_zone_identifier():
    with pytest.raises(ValueError, match="zone identifier"):
        validate_ip("fe80::1%eth0")


def test_validates_all_resolved_addresses_and_rejects_empty_results():
    assert validate_ip_addresses(["8.8.8.8", "2001:4860:4860::8888"]) == (
        "8.8.8.8",
        "2001:4860:4860::8888",
    )

    with pytest.raises(ValueError, match="at least one"):
        validate_ip_addresses([])


def test_all_addresses_must_be_safe():
    with pytest.raises(UnsafeIPAddress, match="private address"):
        validate_ip_addresses(["8.8.8.8", "10.0.0.1"])
