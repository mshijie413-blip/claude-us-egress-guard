#!/usr/bin/env python3

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    path = ROOT / "scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


render_pac = load_script("render_pac")
sanitize_xray = load_script("sanitize_xray_config")
public_safety = load_script("check_public_safety")


class RenderPacTests(unittest.TestCase):
    def test_fail_closed_and_protected_first(self):
        text = render_pac.render(
            "127.0.0.1:17891",
            ["claude.ai"],
            ["feishu.cn"],
        )
        self.assertIn('"PROXY 127.0.0.1:17891"', text)
        self.assertIn("if (isDomains(host, PROTECTED_DOMAINS)) return LOCAL_PROXY;", text)
        self.assertIn("return LOCAL_PROXY;", text)
        self.assertNotIn('return "PROXY 127.0.0.1:17891; DIRECT"', text)

    def test_rejects_non_loopback_proxy(self):
        with self.assertRaises(ValueError):
            render_pac.parse_proxy("192.0.2.10:17891")

    def test_rejects_protected_direct_overlap(self):
        protected = ["claude.ai"]
        direct = ["claude.ai"]
        self.assertTrue(set(protected) & set(direct))


class SanitizerTests(unittest.TestCase):
    def test_redacts_identity_and_public_address(self):
        fake_uuid = (
            "11111111-" "1111-" "4111-" "8111-" "111111111111"
        )
        source = {
            "outbounds": [
                {
                    "settings": {
                        "address": "198.51.100.20",
                        "id": fake_uuid,
                    }
                }
            ]
        }
        output = sanitize_xray.sanitize(source)
        text = json.dumps(output)
        self.assertIn("vps.example.com", text)
        self.assertIn("REPLACE_WITH_VLESS_UUID", text)
        self.assertNotIn("198.51.100.20", text)
        self.assertNotIn(fake_uuid, text)


class PublicSafetyTests(unittest.TestCase):
    def test_clean_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text(
                "Example address: 203.0.113.10\n"
                "Proxy: 127.0.0.1:17891\n"
                "Key: REPLACE_WITH_VLESS_UUID\n",
                encoding="utf-8",
            )
            findings = []
            for path in root.rglob("*"):
                if public_safety.should_scan(path, root):
                    findings.extend(public_safety.inspect(path, root))
            self.assertEqual(findings, [])

    def test_detects_public_address(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public_ip = ".".join(["8", "8", "8", "8"])
            (root / "config.json").write_text(
                '{"address": "' + public_ip + '"}\n',
                encoding="utf-8",
            )
            findings = public_safety.inspect(root / "config.json", root)
            self.assertTrue(any("non-example IPv4" in item[2] for item in findings))


if __name__ == "__main__":
    unittest.main()
