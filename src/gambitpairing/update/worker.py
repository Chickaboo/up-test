"""update worker for updating Gambit Pairing."""

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

import logging

from PyQt6 import QtCore


class UpdateWorker(QtCore.QObject):
    """Worker thread for handling the update process in the background."""

    progress = QtCore.pyqtSignal(int)
    status = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(str)  # Returns extracted path
    error = QtCore.pyqtSignal(str)
    done = QtCore.pyqtSignal(bool, str)  # (success, message or extracted_path)

    def __init__(self, updater):
        super().__init__()
        self.updater = updater

    def run(self):
        """Execute update download and verification process."""
        try:
            # 1. Download
            self.status.emit("Downloading update...")
            zip_path = self.updater.download_update(self.progress.emit)
            if not zip_path:
                self.error.emit("Failed to download update.")
                self.done.emit(False, "Failed to download update.")
                return

            # 2. Verify
            self.status.emit("Verifying checksum...")
            verified = self.updater.verify_checksum(zip_path)
            if not verified:
                self.error.emit(
                    "Checksum verification failed. The file may be corrupted or tampered with."
                )
                self.done.emit(False, "Checksum verification failed.")
                return

            # 3. Extract
            self.status.emit("Extracting update...")
            extracted_path = self.updater.extract_update()
            if not extracted_path:
                self.error.emit("Failed to extract update file.")
                self.done.emit(False, "Failed to extract update file.")
                return
            self.status.emit("Update ready to install.")
            self.finished.emit(extracted_path)
            self.done.emit(True, extracted_path)
        except Exception as e:
            logging.error(f"Error in update worker: {e}", exc_info=True)
            self.error.emit(f"An unexpected error occurred: {e}")
            self.done.emit(False, f"An unexpected error occurred: {e}")
