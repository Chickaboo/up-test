"""Background worker for downloading and preparing an update package."""

# Gambit Pairing

import logging
from typing import Any, Optional

from PyQt6 import QtCore

from .updater import UpdatePackage


class UpdateWorker(QtCore.QObject):
    """Worker thread for handling the update download pipeline."""

    progress = QtCore.pyqtSignal(int)
    status = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(object)  # Optional[UpdatePackage]
    error = QtCore.pyqtSignal(str)
    done = QtCore.pyqtSignal(bool, object)  # (success, UpdatePackage | str)

    def __init__(self, updater: Any) -> None:
        super().__init__()
        self.updater = updater

    def run(self) -> None:
        """Execute update download, verification, and staging."""
        package: Optional[UpdatePackage] = None
        try:
            self.status.emit("Downloading update installer...")
            package = self.updater.download_update(self.progress.emit)
            if not package:
                message = "Failed to download update installer."
                self.error.emit(message)
                self.done.emit(False, message)
                return

            self.status.emit("Verifying download integrity...")
            if not self.updater.verify_package(package):
                self.updater.clear_pending_package(remove_files=True)
                message = (
                    "Checksum verification failed. The download may be corrupted."
                )
                self.error.emit(message)
                self.done.emit(False, message)
                return

            self.status.emit("Update installer ready.")
            self.finished.emit(package)
            self.done.emit(True, package)
        except Exception as exc:  # pragma: no cover - defensive
            logging.error("Error in update worker", exc_info=True)
            message = f"An unexpected error occurred: {exc}"
            self.error.emit(message)
            self.done.emit(False, message)
