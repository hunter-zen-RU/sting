"""
Self-Update Module

Checks for updates from GitHub repository and replaces the installed package.
Uses GitHub Releases API for version checking and downloading.
"""

import os
import sys
import json
import shutil
import tempfile
import zipfile
import subprocess
from typing import Optional

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

from sting import __version__, __github_url__


class SelfUpdater:
    """Handles checking for and applying updates from GitHub."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.repo_url = __github_url__.rstrip("/")
        self.api_url = self.repo_url.replace("github.com", "api.github.com/repos")
        self.current_version = __version__
        self.temp_dir = None

    def _log(self, msg: str):
        """Print verbose message."""
        if self.verbose:
            print(f"[VERBOSE] [Updater] {msg}")

    def get_latest_release(self) -> Optional[dict]:
        """
        Fetch the latest release information from GitHub API.
        Returns dict with tag_name, html_url, assets, etc.
        """
        if not HAVE_REQUESTS:
            print("[!] 'requests' module required for updates.")
            print("    Install with: pip install requests")
            return None

        url = f"{self.api_url}/releases/latest"
        self._log(f"Fetching: {url}")

        try:
            resp = requests.get(url, timeout=15, headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "STING-WiFi-Tool/1.0",
            })

            if resp.status_code == 404:
                print("[!] No releases found on GitHub.")
                print(f"    Check: {self.repo_url}/releases")
                return None
            elif resp.status_code == 403:
                print("[!] GitHub API rate limited. Try again later.")
                return None
            elif resp.status_code != 200:
                print(f"[!] GitHub API error: HTTP {resp.status_code}")
                return None

            data = resp.json()
            return data

        except requests.ConnectionError:
            print("[!] Could not connect to GitHub. Check internet connection.")
            return None
        except requests.Timeout:
            print("[!] GitHub API request timed out.")
            return None
        except json.JSONDecodeError:
            print("[!] Invalid response from GitHub API.")
            return None
        except Exception as e:
            print(f"[!] Update check failed: {e}")
            return None

    def check_update(self) -> Optional[str]:
        """
        Check if a newer version is available.
        Returns the new version string if available, None otherwise.
        """
        print(f"[*] Current version: v{self.current_version}")
        print(f"[*] Checking: {self.repo_url}/releases/latest")

        release = self.get_latest_release()
        if not release:
            return None

        latest_tag = release.get("tag_name", "").lstrip("v")
        if not latest_tag:
            print("[!] Could not determine latest version.")
            return None

        print(f"[*] Latest version: v{latest_tag}")

        # Compare versions
        if self._version_compare(latest_tag, self.current_version) <= 0:
            print("[*] You are already running the latest version.")
            return None

        print(f"[*] Update available: v{self.current_version} -> v{latest_tag}")
        return latest_tag

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        try:
            parts1 = [int(x) for x in v1.split(".")]
            parts2 = [int(x) for x in v2.split(".")]
            # Pad shorter version with zeros
            while len(parts1) < len(parts2):
                parts1.append(0)
            while len(parts2) < len(parts1):
                parts2.append(0)

            for a, b in zip(parts1, parts2):
                if a < b:
                    return -1
                if a > b:
                    return 1
            return 0
        except ValueError:
            # If non-numeric versions, string compare
            if v1 < v2:
                return -1
            if v1 > v2:
                return 1
            return 0

    def download_update(self, version: str) -> Optional[str]:
        """
        Download the latest release zip file.
        Returns the path to the downloaded zip, or None on failure.
        """
        release = self.get_latest_release()
        if not release:
            return None

        # Find the source code zip asset
        zip_url = None
        for asset in release.get("assets", []):
            name = asset.get("name", "")
            if name.endswith(".zip"):
                zip_url = asset.get("browser_download_url")
                break

        # Fallback to the source code archive
        if not zip_url:
            tag = release.get("tag_name", f"v{version}")
            zip_url = f"{self.repo_url}/archive/refs/tags/{tag}.zip"
            self._log(f"No asset zip found, using: {zip_url}")

        if not zip_url:
            print("[!] Could not find download URL for update.")
            return None

        # Create temp directory
        self.temp_dir = tempfile.mkdtemp(prefix="sting_update_")
        zip_path = os.path.join(self.temp_dir, "sting_update.zip")

        print(f"[*] Downloading update from GitHub...")
        self._log(f"URL: {zip_url}")

        try:
            resp = requests.get(zip_url, timeout=60, stream=True)
            if resp.status_code != 200:
                print(f"[!] Download failed: HTTP {resp.status_code}")
                return None

            total = int(resp.headers.get("content-length", 0))
            downloaded = 0

            with open(zip_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total > 0 and self.verbose:
                            pct = int(downloaded * 100 / total)
                            print(f"[VERBOSE] Download progress: {pct}%", end="\r")

            print(f"[*] Downloaded: {zip_path} ({downloaded / 1024:.1f} KB)")
            return zip_path

        except Exception as e:
            print(f"[!] Download failed: {e}")
            return None

    def install_update(self, zip_path: str) -> bool:
        """
        Extract the downloaded zip and replace the current installation with the new code.
        """
        extract_dir = os.path.join(self.temp_dir, "sting_extracted")
        os.makedirs(extract_dir, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(extract_dir)
        except zipfile.BadZipFile:
            print("[!] Downloaded file is corrupted (not a valid zip).")
            return False

        # Find the package directory inside the extracted archive
        # Structure: sting-version/sting/ or similar
        extracted_items = os.listdir(extract_dir)
        if not extracted_items:
            print("[!] Empty archive.")
            return False

        # The top-level directory is usually the repo root
        repo_root = os.path.join(extract_dir, extracted_items[0])
        if not os.path.isdir(repo_root):
            repo_root = extract_dir

        # Find the sting package directory
        source_pkg = os.path.join(repo_root, "sting")
        if not os.path.isdir(source_pkg):
            # Try alternate location
            source_pkg = os.path.join(repo_root, "sting", "sting")

        if not os.path.isdir(source_pkg):
            print(f"[!] Could not find 'sting' package in the downloaded archive.")
            print(f"    Extracted to: {extract_dir}")
            return False

        # Determine current package location
        current_pkg = os.path.dirname(os.path.abspath(__file__))
        current_root = os.path.dirname(current_pkg)

        self._log(f"Source: {source_pkg}")
        self._log(f"Current: {current_pkg}")

        print(f"[*] Installing update...")

        # Copy new files over current installation
        try:
            for item in os.listdir(source_pkg):
                src = os.path.join(source_pkg, item)
                dst = os.path.join(current_pkg, item)

                if os.path.isdir(src):
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)

            print(f"[*] Update installed successfully!")
            print(f"[*] Restart STING to use v{self._get_new_version(source_pkg)}")
            return True

        except PermissionError:
            print("[!] Permission denied during update.")
            print("    Try running with administrator/root privileges.")
            return False
        except Exception as e:
            print(f"[!] Update installation failed: {e}")
            return False

    def _get_new_version(self, pkg_dir: str) -> str:
        """Read version from the updated package's __init__.py."""
        init_path = os.path.join(pkg_dir, "__init__.py")
        try:
            with open(init_path) as f:
                for line in f:
                    if line.startswith("__version__"):
                        return line.split("=")[1].strip().strip("\"'")
        except Exception:
            pass
        return "?"

    def cleanup(self):
        """Remove temporary files."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                self._log(f"Cleaned up: {self.temp_dir}")
            except Exception as e:
                self._log(f"Cleanup warning: {e}")

    def run_update(self, verbose: bool = False) -> bool:
        """
        Run the full update process: check -> download -> install.
        Returns True if successful, False otherwise.
        """
        self.verbose = verbose

        try:
            new_version = self.check_update()
            if not new_version:
                self.cleanup()
                return True  # No update needed is not a failure

            print()
            zip_path = self.download_update(new_version)
            if not zip_path:
                self.cleanup()
                return False

            print()
            success = self.install_update(zip_path)
            self.cleanup()
            return success

        except Exception as e:
            print(f"[!] Update failed: {e}")
            self.cleanup()
            return False
