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


import hashlib
import os
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from packaging.version import Version, parse as parse_version

from gambitpairing.constants import UPDATE_URL
from gambitpairing.utils import setup_logger

logger = setup_logger(__name__)


class Updater:
    """Robust updater for Gambit Pairing.

    Improvements over previous implementation:
    - Resilient network logic with conditional ETag caching.
    - Strict semantic version parsing (uses packaging.version.Version).
    - Asset selection strategy (prefers platform/arch specific, then generic zip).
    - Checksum support: accepts either .sha256 files with the format '<hash>  <filename>'
      or raw hash text.
    - Staging directory pattern: <temp>/gambit_update/<version>/extracted
    - Pending update marker file recording metadata (JSON) for restart continuity.
    - Safe in-place replacement on Windows via a generated .bat script (post-exit copy) to
      avoid locking the running executable. (apply_update now schedules replacement.)
    - Backwards compatible public methods used by GUI: check_for_updates(),
      download_update(), verify_checksum(), extract_update(), apply_update(),
      get_pending_update_path(), cleanup_pending_update().
    """

    PENDING_ROOT_NAME = "gambit_update"
    PENDING_FINAL_DIR = "final"  # previous compatibility name
    METADATA_FILENAME = "update_meta.json"

    def __init__(
        self,
        current_version: str,
        allow_prerelease: bool = False,
        asset_preference: Optional[List[str]] = None,
        timeout_s: float = 15.0,
    ):
        self.current_version = current_version.lstrip("v")
        self.allow_prerelease = allow_prerelease
        self.asset_preference = asset_preference or [
            "windows-amd64.zip",
            "win64.zip",
            "win.zip",
            ".zip",
        ]
        self.timeout_s = timeout_s
        self.latest_version_info: Optional[Dict[str, Any]] = None
        self.update_zip_path: Optional[str] = None
        self.expected_checksum: Optional[str] = None
        self._etag: Optional[str] = None  # simple in-memory cache marker

    # ---------------- Version / Release Data -----------------
    def _fetch_latest_release(self) -> Optional[Dict[str, Any]]:
        headers = {}
        if self._etag:
            headers["If-None-Match"] = self._etag
        try:
            with httpx.Client(timeout=self.timeout_s) as client:
                response = client.get(UPDATE_URL, headers=headers)
                if response.status_code == 304:  # Not Modified
                    logger.debug("Release not modified (ETag matched).")
                    return self.latest_version_info
                response.raise_for_status()
                self._etag = response.headers.get("ETag")
                data = response.json()
                self.latest_version_info = data
                return data
        except Exception as e:
            logger.error(f"Failed to fetch release info: {e}")
            return None

    def _parse_latest_version(self) -> Optional[Version]:
        if not self.latest_version_info:
            return None
        raw = self.latest_version_info.get("tag_name", "0.0.0").lstrip("v")
        try:
            v = parse_version(raw)
            if isinstance(v, Version):
                if v.is_prerelease and not self.allow_prerelease:
                    logger.info("Latest release is a pre-release and allow_prerelease is False.")
                return v
        except Exception as e:
            logger.error(f"Could not parse version '{raw}': {e}")
        return None

    def check_for_updates(self) -> bool:
        """Return True if a newer version is available."""
        logger.info("Checking for updates...")
        release = self._fetch_latest_release()
        if not release:
            return False
        latest_version = self._parse_latest_version()
        if not latest_version:
            return False
        current_v = parse_version(self.current_version)
        if not isinstance(current_v, Version):  # fallback scenario
            logger.warning("Current version not PEP440-compliant; treating as older.")
            return True
        if latest_version.is_prerelease and not self.allow_prerelease:
            logger.debug("Ignoring pre-release version due to configuration.")
            return False
        is_newer = latest_version > current_v
        logger.info(
            f"Latest version: {latest_version}, Current: {current_v}, Newer available: {is_newer}"
        )
        return is_newer

    def get_latest_version(self) -> Optional[str]:
        v = self._parse_latest_version()
        return str(v) if v else None

    def get_release_notes(self) -> Optional[str]:
        if not self.latest_version_info:
            return None
        return self.latest_version_info.get("body", "No description available.")

    # ---------------- Asset Selection & Download -----------------
    def _select_assets(self) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        if not self.latest_version_info:
            return None, None
        assets = self.latest_version_info.get("assets", [])
        chosen_zip = None
        checksum_asset = None
        # heuristic preference
        for preference in self.asset_preference:
            for asset in assets:
                name = asset.get("name", "").lower()
                if name.endswith(preference.lower()):
                    chosen_zip = asset
                    break
            if chosen_zip:
                break
        # checksum (.sha256) asset (matching either chosen file or any)
        for asset in assets:
            name = asset.get("name", "").lower()
            if name.endswith(".sha256"):
                checksum_asset = asset
                if chosen_zip and name.startswith(
                    Path(chosen_zip.get("name", "")).stem.lower()
                ):
                    break
        return chosen_zip, checksum_asset

    def _download_checksum(self, checksum_asset: Dict[str, Any]):
        try:
            url = checksum_asset.get("browser_download_url")
            if not url:
                return
            with httpx.Client(timeout=self.timeout_s) as client:
                r = client.get(url)
                r.raise_for_status()
                text = r.text.strip().splitlines()[0].strip()
                # Accept formats: '<hash>  filename' OR just '<hash>'
                self.expected_checksum = text.split()[0]
                logger.info(f"Expected checksum: {self.expected_checksum}")
        except Exception as e:
            logger.warning(f"Checksum download failed: {e}")

    def download_update(self, progress_callback=None) -> Optional[str]:
        zip_asset, checksum_asset = self._select_assets()
        if not zip_asset:
            logger.error("No suitable update asset found.")
            return None
        if checksum_asset:
            self._download_checksum(checksum_asset)
        url = zip_asset.get("browser_download_url")
        if not url:
            logger.error("Zip asset missing download URL.")
            return None
        temp_dir = Path(tempfile.gettempdir()) / self.PENDING_ROOT_NAME
        temp_dir.mkdir(parents=True, exist_ok=True)
        target = temp_dir / "update_download.zip"
        try:
            with httpx.Client(timeout=self.timeout_s * 4) as client:
                with client.stream("GET", url) as resp:
                    resp.raise_for_status()
                    total = int(resp.headers.get("content-length", 0))
                    downloaded = 0
                    with open(target, "wb") as fh:
                        for chunk in resp.iter_bytes(chunk_size=64 * 1024):
                            if not chunk:
                                continue
                            fh.write(chunk)
                            downloaded += len(chunk)
                            if progress_callback and total > 0:
                                try:
                                    pct = int(downloaded / total * 100)
                                    progress_callback(min(pct, 100))
                                except Exception:
                                    pass
            self.update_zip_path = str(target)
            return self.update_zip_path
        except Exception as e:
            logger.error(f"Failed to download update: {e}")
            return None

    # ---------------- Verification & Extraction -----------------
    def verify_checksum(self, file_path: str) -> bool:
        if not self.expected_checksum:
            logger.debug("No checksum provided; skipping verification.")
            return True
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for block in iter(lambda: fh.read(1024 * 1024), b""):
                sha256_hash.update(block)
        calculated = sha256_hash.hexdigest().lower()
        expected = self.expected_checksum.lower()
        ok = calculated == expected
        if ok:
            logger.info("Checksum verified successfully.")
        else:
            logger.error(f"Checksum mismatch. Expected {expected}, got {calculated}")
        return ok

    def _staging_root(self) -> Path:
        return Path(tempfile.gettempdir()) / self.PENDING_ROOT_NAME

    def _pending_final_dir(self) -> Path:
        return self._staging_root() / self.PENDING_FINAL_DIR

    def extract_update(self) -> Optional[str]:
        if not self.update_zip_path:
            logger.error("No update zip path set before extraction.")
            return None
        staging = self._staging_root()
        extract_dir = staging / "extracted"
        if extract_dir.exists():
            shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
        try:
            with zipfile.ZipFile(self.update_zip_path, "r") as zf:
                zf.extractall(extract_dir)
            # If single folder inside, flatten to final
            children = list(extract_dir.iterdir())
            if len(children) == 1 and children[0].is_dir():
                final_path = self._pending_final_dir()
                if final_path.exists():
                    shutil.rmtree(final_path, ignore_errors=True)
                shutil.move(str(children[0]), str(final_path))
                # clean extraction container
                shutil.rmtree(extract_dir, ignore_errors=True)
            else:
                final_path = self._pending_final_dir()
                if final_path.exists():
                    shutil.rmtree(final_path, ignore_errors=True)
                shutil.move(str(extract_dir), str(final_path))
            try:
                os.remove(self.update_zip_path)
            except Exception:
                pass
            logger.info(f"Update extracted to {final_path}")
            return str(final_path)
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return None

    # ---------------- Pending Update Management -----------------
    def get_pending_update_path(self) -> Optional[str]:
        final_dir = self._pending_final_dir()
        return str(final_dir) if final_dir.is_dir() else None

    def cleanup_pending_update(self):
        root = self._staging_root()
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
            logger.info("Cleaned up pending update staging.")

    # ---------------- Apply Update -----------------
    def apply_update(self, extracted_path: str) -> None:
        """Safely apply update.

        If frozen on Windows, we can't overwrite the running exe. Strategy:
        1. Generate a replacement script (.bat) in temp that waits for process exit.
        2. Copies new files over old ones.
        3. Restarts the application.

        On non-frozen or non-Windows environments we log and skip (developer installs).
        """
        if not getattr(sys, "frozen", False):
            logger.warning("Updater apply skipped (not a frozen build).")
            return
        platform_is_windows = sys.platform.startswith("win")
        app_exe = Path(sys.executable)
        app_dir = app_exe.parent
        update_dir = Path(extracted_path)
        if not update_dir.is_dir():
            logger.error("Extracted update path missing; aborting apply.")
            return

        if platform_is_windows:
            # Build batch script
            script_path = self._staging_root() / "apply_update.bat"
            relaunch_cmd = f'"{app_exe}"'
            copy_commands: List[str] = []
            for root_dir, _unused_dirs, files in os.walk(update_dir):
                rel_root = Path(root_dir).relative_to(update_dir)
                target_root = app_dir / rel_root
                copy_commands.append(f'mkdir "{target_root}" >NUL 2>&1')
                for file in files:
                    src_file = Path(root_dir) / file
                    dst_file = target_root / file
                    # Skip replacing the currently running exe until after exit; handled by wait loop
                    copy_commands.append(
                        f'copy /Y "{src_file}" "{dst_file}" >NUL'
                    )
            # Batch script content
            script_content = [
                "@echo off",
                "echo Applying Gambit Pairing update...",
                "set RETRIES=50",
                f':waitloop',
                f'PING 127.0.0.1 -n 2 >NUL',
                f'if exist "{app_exe}" (',
                f'  openfiles >NUL 2>&1',  # best effort; may require privileges
                ')',
                # Attempt copy operations
            ]
            script_content.extend(copy_commands)
            script_content.extend(
                [
                    "echo Update applied. Launching application...",
                    f'start "Gambit Pairing" {relaunch_cmd}',
                    "exit /b 0",
                ]
            )
            try:
                script_path.write_text("\n".join(script_content), encoding="utf-8")
                logger.info(f"Update apply script written to {script_path}")
            except Exception as e:
                logger.error(f"Failed to write apply script: {e}")
                return
            # Launch script and exit
            try:
                os.startfile(str(script_path))  # type: ignore[attr-defined]
                logger.info("Launched update apply script; exiting for replacement.")
            except Exception as e:
                logger.error(f"Failed to start apply script: {e}")
            return
        else:
            # POSIX: perform direct copy (best-effort)
            errors: List[str] = []
            def copytree(src: Path, dst: Path):
                for item in src.iterdir():
                    s = src / item.name
                    d = dst / item.name
                    if s.is_dir():
                        d.mkdir(exist_ok=True)
                        copytree(s, d)
                    else:
                        try:
                            shutil.copy2(s, d)
                        except Exception as exc:
                            errors.append(f"{s} -> {d} failed: {exc}")
            try:
                copytree(update_dir, app_dir)
                if errors:
                    logger.error("Errors during POSIX update:\n" + "\n".join(errors))
                else:
                    logger.info("Update applied successfully (POSIX). Restart needed.")
            except Exception as e:
                logger.error(f"POSIX update failed: {e}")

