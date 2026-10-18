import asyncio
import pytest
from backend.app.analyzers.url_analyzer import (
    is_private_ip,
    check_brand_impersonation,
    analyze_url
)

def test_is_private_ip():
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("localhost") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("8.8.8.8") is False

def test_check_brand_impersonation():
    assert check_brand_impersonation("sbi-login.xyz") is True
    assert check_brand_impersonation("paytm-verify.com") is True
    assert check_brand_impersonation("google.com") is False
    assert check_brand_impersonation("www.amazon.com") is False
    assert check_brand_impersonation("amazon-security.net") is True

def test_ssrf_rejection():
    with pytest.raises(ValueError, match="Private and local"):
        asyncio.run(analyze_url("http://127.0.0.1/admin"))

    with pytest.raises(ValueError, match="Private and local"):
        asyncio.run(analyze_url("http://localhost:8080"))

    with pytest.raises(ValueError, match="Private and local"):
        asyncio.run(analyze_url("http://192.168.1.100"))

def test_real_brand_domains_are_not_flagged():
    for host in ("login.microsoftonline.com", "accounts.google.com",
                 "s3.us-east-2.amazonaws.com", "www.amazon.in"):
        assert not check_brand_impersonation(host)


def test_lookalike_brand_domains_are_flagged():
    for host in ("paypal-login.vercel.app", "secure-paypal-login.com",
                 "login.webwindos-whatsapp.com.cn"):
        assert check_brand_impersonation(host)

def test_hosts_on_brand_infrastructure_are_not_flagged():
    assert not check_brand_impersonation("mybucket.s3.us-east-2.amazonaws.com")


def test_brand_names_on_someone_elses_storage_are_flagged():
    assert check_brand_impersonation("paypal-login.s3.us-east-2.amazonaws.com")