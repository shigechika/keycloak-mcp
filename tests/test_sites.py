"""Tests for SiteClassifier."""

import os
import tempfile

from keycloak_mcp.sites import SiteClassifier


def _write_ini(content: str) -> str:
    """Write a temporary INI file and return its path."""
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".ini", delete=False)
    f.write(content)
    f.close()
    return f.name


SAMPLE_INI = """\
[LAW]
name = Faculty of Law
ipv4 = 10.0.1.0/24
ipv6 = 2001:db8:1::/48

[ENG]
name = Faculty of Engineering
ipv4 = 10.0.2.0/24, 10.0.3.0/24
"""


class TestSiteClassifier:
    def test_classify_ipv4_match(self):
        path = _write_ini(SAMPLE_INI)
        try:
            os.environ["KEYCLOAK_SITES_INI"] = path
            sc = SiteClassifier()
            assert sc.available is True
            assert sc.classify("10.0.1.5") == "Faculty of Law"
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
            os.unlink(path)

    def test_classify_ipv6_match(self):
        path = _write_ini(SAMPLE_INI)
        try:
            os.environ["KEYCLOAK_SITES_INI"] = path
            sc = SiteClassifier()
            assert sc.classify("2001:db8:1::1") == "Faculty of Law"
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
            os.unlink(path)

    def test_classify_multiple_ranges(self):
        path = _write_ini(SAMPLE_INI)
        try:
            os.environ["KEYCLOAK_SITES_INI"] = path
            sc = SiteClassifier()
            assert sc.classify("10.0.2.100") == "Faculty of Engineering"
            assert sc.classify("10.0.3.50") == "Faculty of Engineering"
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
            os.unlink(path)

    def test_classify_no_match(self):
        path = _write_ini(SAMPLE_INI)
        try:
            os.environ["KEYCLOAK_SITES_INI"] = path
            sc = SiteClassifier()
            assert sc.classify("192.168.1.1") is None
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
            os.unlink(path)

    def test_classify_invalid_ip(self):
        path = _write_ini(SAMPLE_INI)
        try:
            os.environ["KEYCLOAK_SITES_INI"] = path
            sc = SiteClassifier()
            assert sc.classify("not-an-ip") is None
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
            os.unlink(path)

    def test_no_ini_file(self):
        os.environ.pop("KEYCLOAK_SITES_INI", None)
        sc = SiteClassifier()
        assert sc.available is False
        assert sc.classify("10.0.1.5") is None

    def test_nonexistent_file(self):
        os.environ["KEYCLOAK_SITES_INI"] = "/nonexistent/path.ini"
        try:
            sc = SiteClassifier()
            assert sc.available is False
        finally:
            os.environ.pop("KEYCLOAK_SITES_INI", None)
