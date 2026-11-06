"""Tests for the self-updater's pure helpers and safe extraction."""

import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch

from sting.updater import SelfUpdater


class FakeResponse:
    def __init__(self, status_code, payload, text=""):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = {}

    def json(self):
        return self._payload


class UpdaterTests(unittest.TestCase):
    def setUp(self):
        self.updater = SelfUpdater(repo_url="https://github.com/example/sting")

    def test_repository_urls(self):
        self.assertEqual(
            self.updater.api_url,
            "https://api.github.com/repos/example/sting",
        )
        self.assertEqual(
            SelfUpdater._to_api_url("git@github.com:example/sting.git"),
            "https://api.github.com/repos/example/sting",
        )
        self.assertIsNone(SelfUpdater._to_api_url("https://example.com/repo"))

    def test_version_compare(self):
        compare = self.updater._version_compare
        self.assertEqual(compare("1.1.0", "1.0.0"), 1)
        self.assertEqual(compare("1.0.0", "1.0.0"), 0)
        self.assertEqual(compare("1.0", "1.0.0"), 0)
        self.assertEqual(compare("0.9.9", "1.0.0"), -1)
        self.assertEqual(compare("2.0.0-beta", "2.0.0"), -1)
        self.assertEqual(compare("2.0.0", "2.0.0-beta"), 1)

    def test_expected_digest(self):
        self.assertEqual(
            SelfUpdater._expected_digest({"digest": "sha256:ABCDEF"}),
            "abcdef",
        )
        self.assertIsNone(SelfUpdater._expected_digest({}))
        self.assertIsNone(
            SelfUpdater._expected_digest({"digest": "sha512:abcdef"})
        )

    def test_safe_extract_valid(self):
        with tempfile.TemporaryDirectory() as temp:
            archive_path = os.path.join(temp, "ok.zip")
            destination = os.path.join(temp, "out")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("sting/__init__.py", "__version__ = '1.2.3'\n")
            SelfUpdater._safe_extract(archive_path, destination)
            self.assertTrue(
                os.path.isfile(os.path.join(destination, "sting", "__init__.py"))
            )

    def test_safe_extract_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            archive_path = os.path.join(temp, "evil.zip")
            destination = os.path.join(temp, "out")
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../evil.txt", "pwned")
            with self.assertRaises(ValueError):
                SelfUpdater._safe_extract(archive_path, destination)
            self.assertFalse(os.path.exists(os.path.join(temp, "evil.txt")))

    def test_find_package_dir(self):
        with tempfile.TemporaryDirectory() as temp:
            package = os.path.join(temp, "archive-main", "sting")
            os.makedirs(package)
            open(os.path.join(package, "__init__.py"), "w", encoding="utf-8").close()
            found = SelfUpdater._find_package_dir(temp)
            self.assertEqual(os.path.abspath(found), os.path.abspath(package))

    def test_read_new_version(self):
        with tempfile.TemporaryDirectory() as temp:
            init_path = os.path.join(temp, "__init__.py")
            with open(init_path, "w", encoding="utf-8") as handle:
                handle.write('__version__ = "9.9.9"\n')
            self.assertEqual(SelfUpdater._get_new_version(temp), "9.9.9")

    def test_falls_back_to_latest_tag(self):
        responses = [
            FakeResponse(404, {}),
            FakeResponse(200, [{"name": "v1.2.3"}]),
        ]
        with patch("sting.updater.requests.get", side_effect=responses):
            release = self.updater.get_latest_release()
        self.assertIsNotNone(release)
        self.assertEqual(release["tag_name"], "v1.2.3")
        self.assertEqual(release["assets"], [])
        self.assertIsNone(self.updater.last_error)

    def test_falls_back_to_default_branch(self):
        responses = [
            FakeResponse(404, {}),
            FakeResponse(200, []),
            FakeResponse(200, {"default_branch": "main"}),
            FakeResponse(200, {}, text='__version__ = "1.3.0"\n'),
        ]
        with patch("sting.updater.requests.get", side_effect=responses):
            release = self.updater.get_latest_release()
        self.assertIsNotNone(release)
        self.assertEqual(release["tag_name"], "v1.3.0")
        self.assertTrue(release["archive_url"].endswith("/main.zip"))
        self.assertIsNone(self.updater.last_error)


if __name__ == "__main__":
    unittest.main()
