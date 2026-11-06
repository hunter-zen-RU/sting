"""Self-update module.

Checks GitHub Releases for a newer version, downloads the release archive,
verifies its SHA-256 digest when GitHub provides one, and replaces the
installed package with backup/rollback protection.
"""

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from typing import Optional

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:  # pragma: no cover - depends on the environment
    HAVE_REQUESTS = False

from sting import __github_url__, __version__

USER_AGENT = f"STING-WiFi-Tool/{__version__}"


class SelfUpdater:
    """Check for and apply updates from a GitHub repository."""

    def __init__(self, verbose: bool = False, repo_url: Optional[str] = None):
        self.verbose = verbose
        self.repo_url = (repo_url or os.environ.get("STING_REPO_URL")
                         or __github_url__).rstrip("/")
        self.api_url = self._to_api_url(self.repo_url)
        self.current_version = __version__
        self.temp_dir: Optional[str] = None
        self.last_error: Optional[str] = None
        self._release: Optional[dict] = None

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _to_api_url(repo_url: str) -> Optional[str]:
        """Convert a GitHub web URL to its REST API repository URL."""
        if repo_url.startswith("git@github.com:"):
            path = repo_url.split(":", 1)[1]
        elif "github.com/" in repo_url:
            path = repo_url.split("github.com/", 1)[1]
        else:
            return None
        path = path.strip("/")
        if path.endswith(".git"):
            path = path[:-4]
        return f"https://api.github.com/repos/{path}" if path else None

    def _log(self, message: str) -> None:
        if self.verbose:
            print(f"[VERBOSE] [Updater] {message}")

    def _fail(self, message: str) -> None:
        self.last_error = message
        print(f"[!] {message}")

    def _ensure_temp_dir(self) -> str:
        if self.temp_dir is None:
            self.temp_dir = tempfile.mkdtemp(prefix="sting_update_")
        return self.temp_dir

    # -- release metadata ----------------------------------------------------

    def get_latest_release(self, force: bool = False) -> Optional[dict]:
        """Fetch (and cache) the latest GitHub release."""
        if self._release is not None and not force:
            return self._release

        self.last_error = None
        if not HAVE_REQUESTS:
            self._fail("'requests' module required for updates. "
                       "Install with: pip install requests")
            return None
        if not self.api_url:
            self._fail(f"Unsupported repository URL: {self.repo_url}")
            return None

        url = f"{self.api_url}/releases/latest"
        self._log(f"Fetching: {url}")

        try:
            response = requests.get(url, timeout=15, headers={
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": USER_AGENT,
            })

            if response.status_code == 404:
                return self._get_latest_tag()
            if response.status_code == 403:
                self._fail("GitHub API rate limited. Try again later.")
                return None
            if response.status_code != 200:
                self._fail(f"GitHub API error: HTTP {response.status_code}")
                return None

            self._release = response.json()
            return self._release

        except requests.ConnectionError:
            self._fail("Could not connect to GitHub. Check your internet connection.")
        except requests.Timeout:
            self._fail("GitHub API request timed out.")
        except json.JSONDecodeError:
            self._fail("Invalid response from GitHub API.")
        except Exception as exc:
            self._fail(f"Update check failed: {exc}")
        return None

    def _get_latest_tag(self) -> Optional[dict]:
        """Fall back to the newest git tag when no GitHub Release exists."""
        self._log("No releases found; checking tags...")
        try:
            response = requests.get(
                f"{self.api_url}/tags",
                params={"per_page": 1},
                timeout=15,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": USER_AGENT,
                },
            )
            if response.status_code == 200:
                tags = response.json()
                if tags:
                    tag = str(tags[0].get("name", "")).strip()
                    if tag:
                        print(f"[*] No release found; using latest tag {tag}.")
                        self._release = {
                            "tag_name": tag,
                            "name": tag,
                            "assets": [],
                            "html_url": f"{self.repo_url}/releases/tag/{tag}",
                        }
                        return self._release
            return self._get_default_branch_update()
        except requests.ConnectionError:
            self._fail("Could not connect to GitHub. Check your internet connection.")
        except requests.Timeout:
            self._fail("GitHub API request timed out.")
        except json.JSONDecodeError:
            self._fail("Invalid response from GitHub API.")
        except Exception as exc:
            self._fail(f"Update check failed: {exc}")
        return None

    def _get_default_branch_update(self) -> Optional[dict]:
        """Fall back to the default branch's version when no tags exist."""
        self._log("No tags found; checking the default branch...")
        try:
            response = requests.get(
                self.api_url,
                timeout=15,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": USER_AGENT,
                },
            )
            if response.status_code != 200:
                self._fail("No releases or tags found on GitHub. "
                           f"Check: {self.repo_url}/releases")
                return None

            branch = str(response.json().get("default_branch", "main"))
            repo_path = self.api_url.split("/repos/", 1)[-1]
            raw_url = (f"https://raw.githubusercontent.com/{repo_path}/"
                       f"{branch}/sting/__init__.py")
            raw = requests.get(raw_url, timeout=15,
                               headers={"User-Agent": USER_AGENT})
            if raw.status_code != 200:
                self._fail("Could not read the version from the default branch.")
                return None

            match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", raw.text)
            if not match:
                self._fail("Could not determine the version on the default branch.")
                return None

            version = match.group(1)
            print(f"[*] No release or tag found; using the {branch} branch "
                  f"(v{version}).")
            self._release = {
                "tag_name": f"v{version}",
                "name": f"{branch} branch",
                "assets": [],
                "archive_url": (f"{self.repo_url}/archive/refs/heads/"
                                f"{branch}.zip"),
                "html_url": self.repo_url,
            }
            return self._release
        except requests.ConnectionError:
            self._fail("Could not connect to GitHub. Check your internet connection.")
        except requests.Timeout:
            self._fail("GitHub API request timed out.")
        except json.JSONDecodeError:
            self._fail("Invalid response from GitHub API.")
        except Exception as exc:
            self._fail(f"Update check failed: {exc}")
        return None

    def check_update(self) -> Optional[str]:
        """Return the latest version string when it is newer, else None."""
        print(f"[*] Current version: v{self.current_version}")
        print(f"[*] Checking: {self.repo_url}/releases/latest")

        release = self.get_latest_release()
        if not release:
            return None

        latest_tag = str(release.get("tag_name", "")).strip().lstrip("vV")
        if not latest_tag:
            self._fail("Could not determine the latest version.")
            return None

        print(f"[*] Latest version: v{latest_tag}")

        if self._version_compare(latest_tag, self.current_version) <= 0:
            print("[*] You are already running the latest version.")
            return None

        print(f"[*] Update available: v{self.current_version} -> v{latest_tag}")
        return latest_tag

    @staticmethod
    def _parse_version(value: str):
        value = str(value).strip().lstrip("vV")
        match = re.match(r"^(\d+(?:\.\d+)*)(?:[-_.]?(.*))?$", value)
        if not match:
            return None
        numbers = tuple(int(part) for part in match.group(1).split("."))
        suffix = match.group(2) or ""
        return numbers, suffix

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two version strings. Returns -1, 0, or 1."""
        first = self._parse_version(v1)
        second = self._parse_version(v2)

        if first is not None and second is not None:
            numbers1, suffix1 = first
            numbers2, suffix2 = second
            length = max(len(numbers1), len(numbers2))
            padded1 = numbers1 + (0,) * (length - len(numbers1))
            padded2 = numbers2 + (0,) * (length - len(numbers2))
            if padded1 < padded2:
                return -1
            if padded1 > padded2:
                return 1

            # A final release is newer than a pre-release with the same number.
            if suffix1 == suffix2:
                return 0
            if not suffix1:
                return 1
            if not suffix2:
                return -1
            return -1 if suffix1 < suffix2 else 1

        value1, value2 = str(v1).lower(), str(v2).lower()
        return -1 if value1 < value2 else (1 if value1 > value2 else 0)

    # -- download ------------------------------------------------------------

    @staticmethod
    def _expected_digest(asset: dict) -> Optional[str]:
        digest = asset.get("digest")
        if not digest:
            return None
        digest = str(digest)
        if digest.startswith("sha256:"):
            return digest.split(":", 1)[1].lower()
        return None

    def download_update(self, version: str,
                        release: Optional[dict] = None) -> Optional[str]:
        """Download the release archive and verify it. Returns its path."""
        self.last_error = None
        if not HAVE_REQUESTS:
            self._fail("'requests' module required for updates.")
            return None

        release = release or self.get_latest_release()
        if not release:
            return None

        zip_url = None
        expected_digest = None
        for asset in release.get("assets", []):
            name = str(asset.get("name", ""))
            if name.endswith(".zip"):
                zip_url = asset.get("browser_download_url")
                expected_digest = self._expected_digest(asset)
                break

        if not zip_url:
            zip_url = release.get("archive_url")
        if not zip_url:
            tag = release.get("tag_name", f"v{version}")
            zip_url = f"{self.repo_url}/archive/refs/tags/{tag}.zip"
            self._log(f"No release asset found, using source archive: {zip_url}")

        temp_dir = self._ensure_temp_dir()
        zip_path = os.path.join(temp_dir, "sting_update.zip")
        print("[*] Downloading update from GitHub...")
        self._log(f"URL: {zip_url}")

        digest = hashlib.sha256()
        downloaded = 0
        try:
            with requests.get(zip_url, timeout=(15, 60), stream=True) as response:
                if response.status_code != 200:
                    self._fail(f"Download failed: HTTP {response.status_code}")
                    return None
                total = int(response.headers.get("content-length", 0) or 0)
                with open(zip_path, "wb") as handle:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        handle.write(chunk)
                        digest.update(chunk)
                        downloaded += len(chunk)
                        if total > 0 and self.verbose:
                            percent = int(downloaded * 100 / total)
                            print(f"[VERBOSE] Download progress: {percent}%", end="\r")
            if self.verbose:
                print()
        except Exception as exc:
            self._fail(f"Download failed: {exc}")
            return None

        if expected_digest and digest.hexdigest() != expected_digest:
            self._fail("Downloaded archive failed SHA-256 verification.")
            return None
        if not expected_digest:
            self._log("No SHA-256 digest provided by GitHub; skipping digest check.")

        if not zipfile.is_zipfile(zip_path):
            self._fail("Downloaded file is not a valid zip archive.")
            return None

        print(f"[*] Downloaded: {zip_path} ({downloaded / 1024:.1f} KB)")
        return zip_path

    # -- installation --------------------------------------------------------

    @staticmethod
    def _safe_extract(zip_path: str, destination: str) -> None:
        """Extract a zip while preventing path traversal (zip-slip)."""
        destination = os.path.abspath(destination)
        os.makedirs(destination, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as archive:
            for member in archive.infolist():
                name = member.filename.replace("\\", "/")
                target = os.path.abspath(os.path.join(destination, name))
                if target != destination and not target.startswith(destination + os.sep):
                    raise ValueError(f"Unsafe path in archive: {member.filename!r}")
                if member.is_dir() or name.endswith("/"):
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with archive.open(member, "r") as source, open(target, "wb") as dest:
                    shutil.copyfileobj(source, dest)

    @staticmethod
    def _find_package_dir(extract_dir: str) -> Optional[str]:
        """Locate the ``sting`` package inside an extracted archive."""
        root_candidates = [extract_dir]
        try:
            root_candidates += [
                os.path.join(extract_dir, item)
                for item in os.listdir(extract_dir)
                if os.path.isdir(os.path.join(extract_dir, item))
            ]
        except OSError:
            return None

        for root in root_candidates:
            package = os.path.join(root, "sting")
            if os.path.isfile(os.path.join(package, "__init__.py")):
                return package
        return None

    def install_update(self, zip_path: str) -> bool:
        """Extract *zip_path* and install it over the current package."""
        self.last_error = None
        temp_dir = self._ensure_temp_dir()
        extract_dir = os.path.join(temp_dir, "sting_extracted")
        try:
            self._safe_extract(zip_path, extract_dir)
        except (zipfile.BadZipFile, ValueError, OSError) as exc:
            self._fail(f"Could not extract the update: {exc}")
            return False

        source_pkg = self._find_package_dir(extract_dir)
        if not source_pkg:
            self._fail("Could not find the 'sting' package in the downloaded archive.")
            return False

        current_pkg = os.path.dirname(os.path.abspath(__file__))
        backup_dir = os.path.join(temp_dir, "backup")
        self._log(f"Source: {source_pkg}")
        self._log(f"Current: {current_pkg}")

        print("[*] Installing update...")
        try:
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            shutil.copytree(current_pkg, backup_dir)
        except OSError as exc:
            self._fail(f"Could not create a backup: {exc}")
            return False

        try:
            for item in os.listdir(source_pkg):
                source = os.path.join(source_pkg, item)
                destination = os.path.join(current_pkg, item)
                if os.path.isdir(source):
                    shutil.copytree(source, destination, dirs_exist_ok=True)
                else:
                    shutil.copy2(source, destination)
        except PermissionError:
            self._restore_backup(current_pkg, backup_dir)
            self._fail("Permission denied during update. "
                       "Try running with administrator/root privileges.")
            return False
        except Exception as exc:
            self._restore_backup(current_pkg, backup_dir)
            self._fail(f"Update installation failed (rolled back): {exc}")
            return False

        shutil.rmtree(backup_dir, ignore_errors=True)
        print("[*] Update installed successfully!")
        print(f"[*] Restart STING to use v{self._get_new_version(source_pkg)}")
        return True

    @staticmethod
    def _restore_backup(current_pkg: str, backup_dir: str) -> None:
        try:
            if os.path.isdir(current_pkg):
                shutil.rmtree(current_pkg)
            shutil.copytree(backup_dir, current_pkg)
        except Exception as exc:
            print(f"[!] Rollback failed: {exc}")

    @staticmethod
    def _get_new_version(pkg_dir: str) -> str:
        """Read the version from the updated package's ``__init__.py``."""
        init_path = os.path.join(pkg_dir, "__init__.py")
        try:
            with open(init_path, encoding="utf-8") as handle:
                for line in handle:
                    match = re.match(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", line)
                    if match:
                        return match.group(1)
        except OSError:
            pass
        return "?"

    # -- orchestration -------------------------------------------------------

    def cleanup(self) -> None:
        """Remove temporary files."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                self._log(f"Cleaned up: {self.temp_dir}")
            except Exception as exc:
                self._log(f"Cleanup warning: {exc}")
        self.temp_dir = None

    def run_update(self, verbose: bool = False) -> bool:
        """Run the full update process: check -> download -> install."""
        self.verbose = verbose
        try:
            new_version = self.check_update()
            if self.last_error:
                return False
            if not new_version:
                return True  # Already up to date.

            print()
            zip_path = self.download_update(new_version)
            if not zip_path:
                return False

            print()
            return self.install_update(zip_path)
        except Exception as exc:
            self._fail(f"Update failed: {exc}")
            return False
        finally:
            self.cleanup()
