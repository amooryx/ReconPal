import socket
import unittest
from unittest.mock import patch

from reconpal.core.scope import Scope, ScopeError


class ScopeResolutionTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(allow=["example.com"])

    @patch("reconpal.core.scope.socket.getaddrinfo")
    def test_allows_public_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]

        self.scope.check("https://example.com")

    @patch("reconpal.core.scope.socket.getaddrinfo")
    def test_blocks_private_addresses(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]

        with self.assertRaisesRegex(ScopeError, "private or loopback"):
            self.scope.check("https://example.com")

    @patch("reconpal.core.scope.socket.getaddrinfo")
    def test_blocks_when_dns_resolution_fails(self, getaddrinfo):
        getaddrinfo.side_effect = socket.gaierror("temporary resolver failure")

        with self.assertRaisesRegex(ScopeError, "could not resolve example.com"):
            self.scope.check("https://example.com")

    @patch("reconpal.core.scope.socket.getaddrinfo")
    def test_blocks_when_dns_returns_no_usable_addresses(self, getaddrinfo):
        getaddrinfo.return_value = []

        with self.assertRaisesRegex(ScopeError, "could not verify an address"):
            self.scope.check("https://example.com")

    @patch("reconpal.core.scope.socket.getaddrinfo")
    def test_allow_private_skips_dns_safety_check(self, getaddrinfo):
        scope = Scope(allow=["example.com"], allow_private=True)

        scope.check("https://example.com")

        getaddrinfo.assert_not_called()


if __name__ == "__main__":
    unittest.main()
