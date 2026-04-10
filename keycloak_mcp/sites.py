"""IP-to-site classification using an INI file.

Loads a sites.ini file specified by KEYCLOAK_SITES_INI environment variable.
Each section maps a site name to IPv4/IPv6 CIDR ranges.

If the environment variable is not set or the file is missing, all IPs are
classified as None (no site label).
"""

import configparser
import ipaddress
import os
from functools import lru_cache


class SiteClassifier:
    """Classify IP addresses into site names using CIDR ranges."""

    def __init__(self):
        self._networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
        self._load()

    def _load(self) -> None:
        path = os.environ.get("KEYCLOAK_SITES_INI", "")
        if not path or not os.path.isfile(path):
            return
        config = configparser.ConfigParser()
        config.read(path, encoding="utf-8")
        for section in config.sections():
            name = config.get(section, "name", fallback=section)
            for key in ("ipv4", "ipv6"):
                raw = config.get(section, key, fallback="")
                for cidr in raw.split(","):
                    cidr = cidr.strip()
                    if cidr:
                        try:
                            net = ipaddress.ip_network(cidr, strict=False)
                            self._networks.append((net, name))
                        except ValueError:
                            pass

    @lru_cache(maxsize=4096)
    def classify(self, ip_str: str) -> str | None:
        """Return site name for an IP, or None if unknown."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return None
        for net, name in self._networks:
            if addr in net:
                return name
        return None

    @property
    def available(self) -> bool:
        """Return True if site data was loaded."""
        return len(self._networks) > 0
