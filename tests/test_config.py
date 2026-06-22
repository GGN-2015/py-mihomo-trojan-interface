from __future__ import annotations

import unittest

from mihomo_trojan_interface.config import build_yaml, parse_trojan_link


class TrojanConfigTests(unittest.TestCase):
    def test_parse_trojan_link(self) -> None:
        node = parse_trojan_link(
            "trojan://password@example.com:443?security=tls&type=tcp&sni=edge.example.com#Example"
        )

        self.assertEqual(node.name, "Example")
        self.assertEqual(node.password, "password")
        self.assertEqual(node.host, "example.com")
        self.assertEqual(node.port, 443)
        self.assertEqual(node.sni, "edge.example.com")
        self.assertEqual(node.network, "tcp")

    def test_build_yaml_contains_mihomo_trojan_node(self) -> None:
        node = parse_trojan_link("trojan://password@example.com:443?type=tcp&sni=edge.example.com#Example")

        content = build_yaml(
            node,
            mixed_port=7890,
            controller="127.0.0.1:9090",
            log_level="debug",
            enable_tun=True,
            server_ips=["203.0.113.10"],
            connect_ip="203.0.113.10",
            skip_cert_verify=True,
            interface_name="",
            node_name="",
            host_aliases=["alias.example.com"],
            direct_hosts=["*.example-direct.com", "198.51.100.7"],
        )

        self.assertIn("mixed-port: 7890", content)
        self.assertIn("log-level: debug", content)
        self.assertIn("  respect-rules: true", content)
        self.assertIn("  proxy-server-nameserver:", content)
        self.assertIn("type: trojan", content)
        self.assertIn("server: 203.0.113.10", content)
        self.assertIn('password: "password"', content)
        self.assertIn('sni: "edge.example.com"', content)
        self.assertIn("  - DOMAIN-SUFFIX,example-direct.com,DIRECT", content)
        self.assertIn("  - IP-CIDR,198.51.100.7/32,DIRECT,no-resolve", content)
        self.assertIn("  - IP-CIDR,203.0.113.10/32,DIRECT,no-resolve", content)


if __name__ == "__main__":
    unittest.main()
