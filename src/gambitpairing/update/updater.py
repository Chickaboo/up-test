# Gambit Pairing
# Copyright (C) 2025  Gambit Pairing developers
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import httpx
from packaging.version import InvalidVersion, Version, parse as parse_version

from gambitpairing import APP_NAME, APP_VERSION
from gambitpairing.constants import UPDATE_URL
from gambitpairing.utils import setup_logger

logger = setup_logger(__name__)


class AssetKind(str, Enum):
    """Known types of update payloads."""

    MSI = "msi"
    EXE = "exe"
    ZIP = "zip"
    DMG = "dmg"
    PKG = "pkg"
    TAR = "tar"
    UNKNOWN = "unknown"

    @classmethod
    def from_name(cls, name: str) -> "AssetKind":
        lower = name.lower()
        if lower.endswith(".msi"):
            return cls.MSI
        if lower.endswith(".exe"):
            return cls.EXE
        if lower.endswith(".zip"):
            return cls.ZIP
        if lower.endswith(".dmg"):
            return cls.DMG
        if lower.endswith(".pkg"):
            return cls.PKG
        if lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            return cls.TAR
        return cls.UNKNOWN

    @property
    def is_installer(self) -> bool:
        return self in {self.MSI, self.EXE, self.DMG, self.PKG}


@dataclass
class UpdateAsset:
    name: str
    url: str
    size: int
    content_type: Optional[str]
    kind: AssetKind
    checksum_url: Optional[str] = None


@dataclass
class UpdatePackage:
    version: str
    asset_name: str
    asset_kind: AssetKind
    file_path: Path
    checksum: Optional[str] = None

    def exists(self) -> bool:
        return self.file_path.exists()

    def to_json(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "asset_name": self.asset_name,
            "asset_kind": self.asset_kind.value,
            "file_path": str(self.file_path),
            "checksum": self.checksum,
            "saved_at": time.time(),
        }

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "UpdatePackage":
        file_path = Path(data.get("file_path", ""))
        kind_raw = data.get("asset_kind", AssetKind.UNKNOWN.value)
        try:
            kind = AssetKind(kind_raw)
        except ValueError:
            kind = AssetKind.UNKNOWN
        return cls(
            version=data.get("version", ""),
            asset_name=data.get("asset_name", file_path.name),
            asset_kind=kind,
            file_path=file_path,
            checksum=data.get("checksum"),
        )


class Updater:
    """Modern updater that downloads installers instead of copying files."""

    DEFAULT_HEADERS = {
        "Accept": "application/vnd.github+json",
        "User-Agent": f"{APP_NAME} Updater/{APP_VERSION}",
    }
    DEFAULT_ASSET_PREFERENCE = [
        "windows-x86_64.msi",
        "win64.msi",
        "-x64.msi",
        ".msi",
        "setup.exe",
        "installer.exe",
        ".exe",
        ".zip",
    ]
    CHECKSUM_SUFFIXES = (".sha256", ".sha512", ".sha1")
    PENDING_STATE_FILE = "pending-update.json"
    MAX_RETRIES = 3
    RETRY_BACKOFF = 1.5

    def __init__(
        self,
        current_version: str,
        allow_prerelease: bool = False,
        asset_preference: Optional[list[str]] = None,
        timeout_s: float = 15.0,
    ) -> None:
        self.current_version = current_version.lstrip("v")
        self.allow_prerelease = allow_prerelease
        self.asset_preference = asset_preference or list(self.DEFAULT_ASSET_PREFERENCE)
        self.timeout_s = timeout_s
        self.latest_release: Optional[Dict[str, Any]] = None
        self._etag: Optional[str] = None
        self._headers = dict(self.DEFAULT_HEADERS)
        self._cache_root: Optional[Path] = None

    # ------------------------------------------------------------------
    # Release metadata helpers
    # ------------------------------------------------------------------
    def _create_client(self, *, timeout: float) -> httpx.Client:
        http_timeout = httpx.Timeout(
            timeout, connect=min(timeout, 10.0), read=timeout, write=timeout
        )
        return httpx.Client(
            timeout=http_timeout,
            headers=self._headers,
            follow_redirects=True,
        )

    def _with_retries(self, description: str, func: Callable[[], Any]) -> Any:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                return func()
            except (httpx.HTTPError, OSError) as exc:
                last_exc = exc
                if attempt == self.MAX_RETRIES:
                    break
                delay = min(self.timeout_s, self.RETRY_BACKOFF ** (attempt - 1))
                logger.warning(
                    "%s failed (attempt %s/%s): %s. Retrying in %.1fs",
                    description,
                    attempt,
                    self.MAX_RETRIES,
                    exc,
                    delay,
                )
                time.sleep(delay)
            except Exception:
                raise
        if last_exc:
            raise last_exc
        raise RuntimeError(f"{description} failed unexpectedly")

    def _fetch_latest_release(self) -> Optional[Dict[str, Any]]:
        headers: Dict[str, str] = {}
        if self._etag:
            headers["If-None-Match"] = self._etag

        def _request() -> Optional[Dict[str, Any]]:
            with self._create_client(timeout=self.timeout_s) as client:
                response = client.get(UPDATE_URL, headers=headers)
                if response.status_code == 304:
                    logger.debug("Release metadata unchanged (ETag cache hit).")
                    return self.latest_release
                response.raise_for_status()
                self._etag = response.headers.get("ETag")
                data = response.json()
                self.latest_release = data
                return data

        try:
            return self._with_retries("Fetch release metadata", _request)
        except Exception as exc:
            logger.error("Failed to fetch release info: %s", exc)
            return None

    def _parse_latest_version(self) -> Optional[Version]:
        if not self.latest_release:
            return None
        raw = str(self.latest_release.get("tag_name", "0.0.0")).lstrip("v")
        try:
            version = parse_version(raw)
        except InvalidVersion:
            logger.error("Could not parse release version '%s'", raw)
            return None
        if not isinstance(version, Version):
            return None
        if version.is_prerelease and not self.allow_prerelease:
            logger.info("Latest release is a pre-release; skipping due to settings.")
            return None
        return version

    def check_for_updates(self) -> bool:
        logger.info("Checking for updates...")
        release = self._fetch_latest_release()
        if not release:
            return False
        latest_version = self._parse_latest_version()
        if not latest_version:
            return False
        current_version = parse_version(self.current_version)
        if not isinstance(current_version, Version):
            logger.warning("Current version is not PEP440-compliant; treating as older.")
            return True
        is_newer = latest_version > current_version
        logger.info(
            "Latest version %s, current version %s. Update available: %s",
            latest_version,
            current_version,
            is_newer,
        )
        return is_newer

    def get_latest_version(self) -> Optional[str]:
        version = self._parse_latest_version()
        return str(version) if version else None

    def get_release_notes(self) -> Optional[str]:
        if not self.latest_release:
            return None
        return self.latest_release.get("body", "")

    # ------------------------------------------------------------------
    # Asset selection & download
    # ------------------------------------------------------------------
    def _select_asset(self) -> Optional[UpdateAsset]:
        if not self.latest_release:
            return None
        assets = self.latest_release.get("assets", [])
        chosen: Optional[Dict[str, Any]] = None
        for preference in self.asset_preference:
            for asset in assets:
                name = asset.get("name", "")
                if not name:
                    continue
                name_lower = name.lower()
                if preference.startswith("."):
                    if name_lower.endswith(preference.lower()):
                        chosen = asset
                        break
                elif preference.lower() in name_lower:
                    chosen = asset
                    break
            if chosen:
                break
        if not chosen and assets:
            chosen = assets[0]
        if not chosen:
            return None
        checksum_url = None
        chosen_stem = Path(chosen.get("name", "")).stem.lower()
        for asset in assets:
            asset_name = asset.get("name", "").lower()
            if not asset_name:
                continue
            if any(asset_name.endswith(suffix) for suffix in self.CHECKSUM_SUFFIXES):
                if Path(asset.get("name", "")).stem.lower().startswith(chosen_stem):
                    checksum_url = asset.get("browser_download_url")
                    break
        return UpdateAsset(
            name=chosen.get("name", ""),
            url=chosen.get("browser_download_url", ""),
            size=int(chosen.get("size", 0) or 0),
            content_type=chosen.get("content_type"),
            kind=AssetKind.from_name(chosen.get("name", "")),
            checksum_url=checksum_url,
        )

    def _download_checksum(self, url: str) -> Optional[str]:
        def _request() -> Optional[str]:
            with self._create_client(timeout=self.timeout_s) as client:
                response = client.get(url)
                response.raise_for_status()
                text = response.text.strip().splitlines()[0].strip()
                return text.split()[0]

        try:
            checksum = self._with_retries("Download checksum", _request)
            if checksum:
                logger.info("Expected checksum: %s", checksum)
            return checksum
        except Exception as exc:
            logger.warning("Checksum download failed: %s", exc)
            return None

    def download_update(
        self, progress_callback: Optional[Callable[[int], None]] = None
    ) -> Optional[UpdatePackage]:
        if not self.latest_release:
            if not self._fetch_latest_release():
                return None
        version = self.get_latest_version()
        if not version:
            logger.error("No version information available for download.")
            return None
        asset = self._select_asset()
        if not asset or not asset.url:
            logger.error("No suitable update asset found.")
            return None

        checksum = None
        if asset.checksum_url:
            checksum = self._download_checksum(asset.checksum_url)

        dest_dir = self._cache_root_for_version(version)
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / asset.name
        temp_file = dest_file.with_suffix(dest_file.suffix + ".part")

        def _download() -> None:
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)  # type: ignore[arg-type]
            with self._create_client(timeout=self.timeout_s * 4) as client:
                with client.stream("GET", asset.url) as response:
                    response.raise_for_status()
                    total_header = response.headers.get("content-length")
                    total = int(total_header) if total_header and total_header.isdigit() else 0
                    downloaded = 0
                    with open(temp_file, "wb") as fh:
                        for chunk in response.iter_bytes(chunk_size=64 * 1024):
                            if not chunk:
                                continue
                            fh.write(chunk)
                            downloaded += len(chunk)
                            if progress_callback:
                                if total > 0:
                                    pct = int(downloaded / total * 100)
                                    progress_callback(min(pct, 99))
                                else:
                                    progress_callback(min(downloaded // (512 * 1024), 99))
            temp_file.replace(dest_file)

        try:
            self._with_retries("Download update asset", _download)
            if progress_callback:
                progress_callback(100)
        except Exception as exc:
            logger.error("Failed to download update: %s", exc)
            if temp_file.exists():
                temp_file.unlink(missing_ok=True)  # type: ignore[arg-type]
            return None

        package = UpdatePackage(
            version=version,
            asset_name=asset.name,
            asset_kind=asset.kind,
            file_path=dest_file,
            checksum=checksum,
        )
        self.save_pending_package(package)
        return package

    # ------------------------------------------------------------------
    # Pending package management & verification
    # ------------------------------------------------------------------
    def verify_package(self, package: UpdatePackage) -> bool:
        if not package.checksum:
            logger.debug("No checksum provided; skipping verification.")
            return True
        if not package.file_path.exists():
            logger.error("Package missing for checksum verification: %s", package.file_path)
            return False
        expected = package.checksum.lower()
        algo = "sha256" if len(expected) == 64 else "sha512"
        hasher = hashlib.new(algo)
        with open(package.file_path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                hasher.update(block)
        calculated = hasher.hexdigest().lower()
        if calculated != expected:
            logger.error(
                "Checksum mismatch. Expected %s but calculated %s", expected, calculated
            )
            return False
        logger.info("Checksum verified successfully.")
        return True

    def save_pending_package(self, package: UpdatePackage) -> None:
        state_path = self._pending_state_path()
        try:
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(json.dumps(package.to_json(), indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed to persist pending package metadata: %s", exc)

    def get_pending_package(self) -> Optional[UpdatePackage]:
        state_path = self._pending_state_path()
        if not state_path.exists():
            return None
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            package = UpdatePackage.from_json(data)
            if not package.exists():
                logger.info("Stored update package no longer exists; cleaning metadata.")
                self.clear_pending_package(remove_files=False)
                return None
            return package
        except Exception as exc:
            logger.warning("Failed to load pending package metadata: %s", exc)
            self.clear_pending_package(remove_files=False)
            return None

    def clear_pending_package(self, *, remove_files: bool) -> None:
        state_path = self._pending_state_path()
        file_path: Optional[Path] = None
        if state_path.exists():
            try:
                data = json.loads(state_path.read_text(encoding="utf-8"))
                file_path = Path(data.get("file_path", "")) if data.get("file_path") else None
            except Exception:
                file_path = None
            state_path.unlink(missing_ok=True)  # type: ignore[arg-type]
        if remove_files and file_path and file_path.exists():
            try:
                file_path.unlink(missing_ok=True)  # type: ignore[arg-type]
            except Exception:
                logger.debug("Failed to delete package file %s", file_path)
            parent = file_path.parent
            if parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()

    # ------------------------------------------------------------------
    # Installation helpers
    # ------------------------------------------------------------------
    def install_package(self, package: UpdatePackage) -> bool:
        if not package.file_path.exists():
            logger.error("Update installer missing: %s", package.file_path)
            return False
        success = False
        try:
            if sys.platform.startswith("win"):
                success = self._launch_windows_installer(package)
            elif sys.platform == "darwin":
                success = self._launch_process(["open", str(package.file_path)])
            else:
                success = self._launch_process(["xdg-open", str(package.file_path)])
        finally:
            if success:
                # Remove metadata so we do not prompt again on next launch.
                self.clear_pending_package(remove_files=False)
        return success

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _cache_root_for_version(self, version: str) -> Path:
        root = self._ensure_cache_root()
        return root / version

    def _pending_state_path(self) -> Path:
        return self._ensure_cache_root() / self.PENDING_STATE_FILE

    def _ensure_cache_root(self) -> Path:
        if self._cache_root is None:
            if sys.platform.startswith("win"):
                base = Path(os.getenv("LOCALAPPDATA", tempfile.gettempdir()))
            else:
                base = Path(tempfile.gettempdir())
            root = base / APP_NAME.replace(" ", "-").lower() / "updates"
            root.mkdir(parents=True, exist_ok=True)
            self._cache_root = root
        return self._cache_root

    def _launch_process(self, args: list[str]) -> bool:
        try:
            subprocess.Popen(args)
            return True
        except Exception as exc:
            logger.error("Failed to launch installer process %s: %s", args, exc)
            return False

    def _launch_windows_installer(self, package: UpdatePackage) -> bool:
        installer_path = str(package.file_path)
        escaped = installer_path.replace("'", "''")
        if package.asset_kind == AssetKind.MSI:
            argument_list = (
                "@('/i','{path}','/passive','/norestart')".format(path=escaped)
            )
            command = (
                "Start-Process -FilePath 'msiexec.exe' "
                f"-ArgumentList {argument_list} -Verb RunAs"
            )
        elif package.asset_kind == AssetKind.EXE:
            command = f"Start-Process -FilePath '{escaped}' -Verb RunAs"
        elif package.asset_kind == AssetKind.ZIP:
            explorer_args = ["explorer.exe", "/select,", installer_path]
            return self._launch_process(explorer_args)
        else:
            command = f"Start-Process -FilePath '{escaped}' -Verb RunAs"
        try:
            completed = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-Command",
                    command,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:
            logger.error("Failed to start installer via PowerShell: %s", exc)
            return False
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            if stderr:
                logger.error("Installer launch failed: %s", stderr)
            else:
                logger.error(
                    "Installer launch failed with return code %s", completed.returncode
                )
            return False
        return True

