#!/usr/bin/env python3
"""
DiskRecovery Pro - Deleted File Recovery Tool
Scans partitions/disk images for deleted files using TSK (The Sleuth Kit)
Requires: pytsk3, PyQt5, Pillow, psutil
Run with: python3 file_recovery.py
Note: Scanning real partitions requires administrator/root privileges.
  - Linux/macOS: sudo python3 file_recovery.py
  - Windows:     Run as Administrator
"""

import sys
import os
import platform
import shutil
import datetime
import subprocess
import tempfile
import traceback
from pathlib import Path

import pytsk3
import psutil

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QListWidget, QListWidgetItem, QFileDialog,
    QStackedWidget, QCheckBox, QLineEdit, QProgressBar, QMessageBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QFrame, QScrollArea,
    QSplitter, QGroupBox, QGridLayout, QComboBox, QAbstractItemView,
    QStatusBar, QSizePolicy, QButtonGroup, QRadioButton, QSpacerItem
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize, QTimer
from PyQt5.QtGui import QIcon, QFont, QColor, QPixmap, QPalette, QImage

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

import struct
import time
import logging
import signal
import binascii
from datetime import datetime

# Detect current OS once at module level
CURRENT_OS = platform.system()   # 'Windows', 'Linux', or 'Darwin'
IS_WINDOWS = CURRENT_OS == "Windows"
IS_LINUX   = CURRENT_OS == "Linux"
IS_MAC     = CURRENT_OS == "Darwin"

# Detect Git Bash / MSYS2 environment on Windows
# Git Bash sets MSYSTEM (e.g. 'MINGW64') and/or runs inside a mintty terminal
IS_GIT_BASH = IS_WINDOWS and bool(
    os.environ.get("MSYSTEM") or          # MINGW64, MINGW32, MSYS
    os.environ.get("TERM_PROGRAM") == "mintty" or
    "git" in os.environ.get("SHELL", "").lower()
)


# ─── Constants ────────────────────────────────────────────────────────────────

FILE_TYPE_GROUPS = {
    "Images":     [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
                   ".webp", ".heic", ".raw", ".cr2", ".nef", ".psd", ".svg"],
    "Videos":     [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm",
                   ".m4v", ".3gp", ".mpeg", ".mpg"],
    "Audio":      [".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
                   ".opus", ".aiff"],
    "Documents":  [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                   ".odt", ".ods", ".odp", ".txt", ".rtf", ".csv"],
    "Archives":   [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"],
    "Code":       [".py", ".js", ".ts", ".html", ".css", ".cpp", ".c", ".java",
                   ".json", ".xml", ".yaml", ".yml", ".sh", ".sql"],
    "Others":     [],   # catch-all toggled by checkbox
}

# ─── Signature-Based Carving Constants ────────────────────────────────────────

FILE_SIGNATURES = {
    'jpg':  [bytes([0xFF, 0xD8, 0xFF, 0xE0]), bytes([0xFF, 0xD8, 0xFF, 0xE1])],
    'png':  [bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])],
    'gif':  [bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]), bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])],
    'pdf':  [bytes([0x25, 0x50, 0x44, 0x46])],
    'zip':  [bytes([0x50, 0x4B, 0x03, 0x04])],
    'docx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'xlsx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'pptx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'mp3':  [bytes([0x49, 0x44, 0x33])],
    'mp4':  [bytes([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70])],
    'avi':  [bytes([0x52, 0x49, 0x46, 0x46])],
}

VALIDATION_PATTERNS = {
    'docx': [b'word/', b'[Content_Types].xml'],
    'xlsx': [b'xl/',   b'[Content_Types].xml'],
    'pptx': [b'ppt/',  b'[Content_Types].xml'],
    'zip':  [b'PK\x01\x02'],
    'pdf':  [b'obj',   b'endobj'],
}

FILE_TRAILERS = {
    'jpg': bytes([0xFF, 0xD9]),
    'png': bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
    'gif': bytes([0x00, 0x3B]),
    'pdf': bytes([0x25, 0x25, 0x45, 0x4F, 0x46]),
}

MAX_FILE_SIZES = {
    'jpg':  30  * 1024 * 1024,
    'png':  50  * 1024 * 1024,
    'gif':  20  * 1024 * 1024,
    'pdf':  100 * 1024 * 1024,
    'zip':  200 * 1024 * 1024,
    'docx': 50  * 1024 * 1024,
    'xlsx': 50  * 1024 * 1024,
    'pptx': 100 * 1024 * 1024,
    'mp3':  50  * 1024 * 1024,
    'mp4':  1024 * 1024 * 1024,
    'avi':  1024 * 1024 * 1024,
}

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #1a1d23;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 13px;
}
QPushButton {
    background-color: #2e7dcc;
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: bold;
}
QPushButton:hover  { background-color: #3a91e0; }
QPushButton:pressed { background-color: #1c5fa0; }
QPushButton:disabled { background-color: #3a3d45; color: #666; }
QPushButton#danger {
    background-color: #c0392b;
}
QPushButton#danger:hover { background-color: #e74c3c; }
QPushButton#success {
    background-color: #27ae60;
}
QPushButton#success:hover { background-color: #2ecc71; }
QGroupBox {
    border: 1px solid #3a3d45;
    border-radius: 8px;
    margin-top: 10px;
    padding-top: 8px;
    font-weight: bold;
    color: #aaa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QTableWidget {
    background-color: #22252d;
    border: 1px solid #3a3d45;
    border-radius: 6px;
    gridline-color: #2d3038;
    color: #ddd;
    selection-background-color: #2e7dcc;
}
QTableWidget::item { padding: 4px 8px; }
QHeaderView::section {
    background-color: #1e2128;
    color: #aaa;
    border: none;
    padding: 6px 8px;
    font-weight: bold;
}
QListWidget {
    background-color: #22252d;
    border: 1px solid #3a3d45;
    border-radius: 6px;
    color: #ddd;
}
QListWidget::item:selected { background-color: #2e7dcc; }
QLineEdit, QComboBox {
    background-color: #22252d;
    border: 1px solid #3a3d45;
    border-radius: 5px;
    padding: 6px 10px;
    color: #ddd;
}
QProgressBar {
    border: none;
    border-radius: 5px;
    background-color: #22252d;
    height: 12px;
    text-align: center;
    color: #fff;
}
QProgressBar::chunk {
    background-color: #2e7dcc;
    border-radius: 5px;
}
QCheckBox { spacing: 8px; color: #ccc; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #555;
    border-radius: 3px;
    background: #22252d;
}
QCheckBox::indicator:checked {
    background: #2e7dcc;
    border-color: #2e7dcc;
}
QLabel#step_label {
    color: #2e7dcc;
    font-size: 18px;
    font-weight: bold;
}
QLabel#section_title {
    font-size: 15px;
    font-weight: bold;
    color: #eee;
}
QFrame#card {
    background-color: #22252d;
    border: 1px solid #3a3d45;
    border-radius: 10px;
}
QStatusBar { color: #888; background: #16181e; }
QScrollBar:vertical {
    background: #1a1d23;
    width: 8px;
}
QScrollBar::handle:vertical {
    background: #3a3d45;
    border-radius: 4px;
}
QScrollBar:horizontal {
    background: #1a1d23;
    height: 8px;
}
QScrollBar::handle:horizontal {
    background: #3a3d45;
    border-radius: 4px;
}

/* ── Drive Card Styles ───────────────────────────────────────── */
QFrame#driveCard {
    background-color: #1e2330;
    border: 1px solid #2e3245;
    border-radius: 10px;
}
QFrame#driveCard:hover {
    border: 1px solid #3a5080;
    background-color: #222840;
}
QFrame#driveCard[selected="true"] {
    border: 2px solid #2e7dcc;
    background-color: #1a2a40;
}
QFrame#driveCardLost {
    background-color: #1e1a1a;
    border: 1px solid #5a2020;
    border-radius: 10px;
}
QFrame#driveCardLost[selected="true"] {
    border: 2px solid #e74c3c;
    background-color: #2a1a1a;
}
QLabel#cardIcon {
    font-size: 26px;
}
QLabel#cardName {
    color: #e8e8e8;
    font-size: 12px;
    font-weight: bold;
}
QLabel#cardSize {
    color: #888;
    font-size: 11px;
}
QLabel#sectionHeader {
    color: #6b8cba;
    font-size: 12px;
    font-weight: bold;
    letter-spacing: 1px;
}
QFrame#quickAccessCard {
    background-color: #1c1f2a;
    border: 1px solid #2a2e3d;
    border-radius: 10px;
}
QFrame#quickAccessCard:hover {
    border: 1px solid #3a4460;
    background-color: #20243a;
}
QFrame#quickAccessCard[selected="true"] {
    border: 2px solid #2e7dcc;
    background-color: #1a2040;
}
QLabel#qaIcon {
    font-size: 22px;
}
QLabel#qaName {
    color: #cccccc;
    font-size: 12px;
    font-weight: bold;
}
"""


# ─── OS Helper Functions ───────────────────────────────────────────────────────

def _is_admin() -> bool:
    """Return True if the process has administrator / root privileges."""
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def _list_system_partitions() -> list:
    """
    Unified method using psutil to scan active disk partitions across all OS types.
    Returns structured data matching the app's DriveCard visual constraints.
    """
    drives = []
    try:
        partitions = psutil.disk_partitions(all=False)
        for partition in partitions:
            # Skip loop devices or empty system mounts on Linux/macOS
            if not partition.fstype or "loop" in partition.device:
                continue
                
            total_bytes = 0
            used_bytes = 0
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                total_bytes = usage.total
                used_bytes = usage.used
            except PermissionError:
                # Retain structural representation if partition security constraints are dropped
                pass

            if IS_WINDOWS:
                mp = partition.mountpoint
                # MSYS2 Python reports mountpoints as POSIX (/c, /g) not Windows (C:\, G:\)
                # Detect and convert both forms to a proper UNC device path.
                import re as _re
                # POSIX form: /g or /g/ (single letter)
                m_posix = _re.match(r'^/([A-Za-z])/?$', mp)
                # Windows form: G:\ or G:
                m_win   = _re.match(r'^([A-Za-z]):[/\\]?', mp)
                if m_posix:
                    drive_letter = m_posix.group(1).upper() + ":"
                elif m_win:
                    drive_letter = m_win.group(1).upper() + ":"
                else:
                    drive_letter = mp.rstrip("\\/")
                unc_path = f"\\\\.\\{drive_letter}" if drive_letter else partition.device
            else:
                unc_path = partition.device

            label_text = f"{partition.mountpoint} ({partition.fstype})" if partition.mountpoint else partition.device

            gb_path = _native_to_gitbash_path(unc_path) if IS_WINDOWS else ""

            drives.append({
                "label":        label_text,
                "path":         unc_path,
                "gitbash_path": gb_path,
                "size_bytes":   total_bytes,
                "used_bytes":   used_bytes,
                "drive_type":   "logical" if partition.fstype else "physical",
                "lost":         False,
            })
    except Exception:
        pass
    return drives


def _list_windows_partitions_native() -> list:
    """
    Windows-only: enumerate logical drives via GetLogicalDrives + GetVolumeInformationW
    + GetDiskFreeSpaceW so we get the real volume label and exact sector/cluster geometry
    (total_sectors is what the banner in Step 3 shows).
    Falls back to _list_system_partitions() on non-Windows or any error.
    """
    if not IS_WINDOWS:
        return _list_system_partitions()
    try:
        import ctypes, string as _string
        drive_bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        drives = []
        sectors_per_cluster = ctypes.c_ulong()
        bytes_per_sector    = ctypes.c_ulong()
        free_clusters       = ctypes.c_ulong()
        total_clusters      = ctypes.c_ulong()

        for i in range(26):
            if not (drive_bitmask & (1 << i)):
                continue
            letter     = _string.ascii_uppercase[i]
            drive_root = f"{letter}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive_root))
            if drive_type not in (3, 4, 6):   # Fixed, Network, RAM disk
                continue

            # Volume label
            vol_buf = ctypes.create_unicode_buffer(260)
            ctypes.windll.kernel32.GetVolumeInformationW(
                ctypes.c_wchar_p(drive_root), vol_buf, ctypes.sizeof(vol_buf),
                None, None, None, None, 0
            )
            volume_name = vol_buf.value.strip() if vol_buf.value.strip() else "Local Disk"

            # Disk geometry
            ok = ctypes.windll.kernel32.GetDiskFreeSpaceW(
                ctypes.c_wchar_p(drive_root),
                ctypes.byref(sectors_per_cluster),
                ctypes.byref(bytes_per_sector),
                ctypes.byref(free_clusters),
                ctypes.byref(total_clusters),
            )
            if not ok:
                continue

            b_sec      = bytes_per_sector.value
            s_clus     = sectors_per_cluster.value
            t_clus     = total_clusters.value
            f_clus     = free_clusters.value
            total_secs = s_clus * t_clus
            total_bytes= total_secs * b_sec
            free_bytes = f_clus * s_clus * b_sec
            used_bytes = total_bytes - free_bytes
            gb_path    = f"/{letter.lower()}/"
            unc_path   = f"\\\\.\\{letter}:"

            drives.append({
                "label":         f"{drive_root} ({volume_name})",
                "volume_name":   volume_name,
                "path":          unc_path,
                "gitbash_path":  gb_path,
                "size_bytes":    total_bytes,
                "used_bytes":    used_bytes,
                "total_sectors": total_secs,
                "sector_size":   b_sec,
                "drive_type":    "logical",
                "lost":          False,
            })
        return drives if drives else _list_system_partitions()
    except Exception:
        return _list_system_partitions()


def _human(size) -> str:
    """Format byte count as human-readable string."""
    try:
        size = int(size)
    except (TypeError, ValueError):
        return "? B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _convert_gitbash_path(path: str) -> str:
    """
    Convert a Git Bash / MSYS2 POSIX-style path to a native Windows path.

    Examples:
        /c/Users/foo/image.dd  →  C:\\Users\\foo\\image.dd
        /c/                    →  \\\\.\\C:
        /dev/sda               →  \\\\.\\PhysicalDrive0   (best-effort hint)
        \\\\.\\D:              →  unchanged
    """
    import re
    p = path.strip()

    # Already a UNC device path — leave it alone
    if p.startswith("\\\\.\\"):
        return p

    # /dev/sdX  →  warn user; return as-is so the caller can show a tip
    if re.match(r'^/dev/', p):
        return p

    # /X/...  →  X:\...  (single letter = drive letter)
    m = re.match(r'^/([A-Za-z])(/.*)?$', p)
    if m:
        drive = m.group(1).upper()
        rest  = (m.group(2) or "").replace("/", "\\")
        if rest in ("", "\\"):
            # Root of drive → raw device path for pytsk3
            return f"\\\\.\\{drive}:"
        return f"{drive}:{rest}"

    return p


def _native_to_gitbash_path(native_path: str) -> str:
    r"""
    Convert a native Windows path to its Git Bash (MSYS2) POSIX equivalent.

    Examples:
        \\.\D:              ->  /d/
        D:\ (or D:)          ->  /d/
        C:\Users\foo\a.img ->  /c/Users/foo/a.img
        \\.\PhysicalDrive0 ->  returned unchanged (no clean POSIX form)
    """
    import re
    p = native_path.strip()

    # \\.\.X:  — raw device path (UNC device namespace)
    # Use startswith + index slice to avoid regex escaping pitfalls
    if p.startswith("\\\\.\\"):
        rest = p[4:]   # everything after \\.\.  e.g. "C:" or "PhysicalDrive0"
        m = re.match(r'^([A-Za-z]):?$', rest)
        if m:
            return f"/{m.group(1).lower()}/"
        return p   # PhysicalDriveN — no clean POSIX equivalent

    # Plain drive root: D:\ or D:
    m = re.match(r'^([A-Za-z]):[/\\]?$', p)
    if m:
        return f"/{m.group(1).lower()}/"

    # Drive + path: D:\Users\foo\file.img -> /d/Users/foo/file.img
    m = re.match(r'^([A-Za-z]):[/\\](.+)', p)
    if m:
        rest = m.group(2).replace("\\", "/")
        return f"/{m.group(1).lower()}/{rest}"

    return p   # already POSIX or unrecognised — return unchanged

def _sanitise_source_path(path: str) -> str:
    """
    Normalise a source path so pytsk3 can open it cleanly.
    Handles native Windows paths, Git Bash POSIX paths, and Linux/macOS device paths.
    """
    if not path:
        return path

    p = path.strip()

    if IS_WINDOWS:
        import re

        # Convert Git Bash / MSYS2 POSIX paths first
        if p.startswith("/") and not p.startswith("//"):
            p = _convert_gitbash_path(p)

        p_bs = p.replace("/", "\\")

        if p_bs.startswith("\\\\.\\"):
            return p_bs.rstrip("\\")

        m = re.match(r'^([A-Za-z]:)[/\\]?$', p_bs)
        if m:
            return f"\\\\.\\{m.group(1).upper()}"

        m2 = re.match(r'^([A-Za-z]:[/\\].+)', p_bs)
        if m2:
            return p_bs   # return backslash form on Windows

    return p


# ─── Worker Threads ────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    progress      = pyqtSignal(int, str)
    file_found    = pyqtSignal(dict)
    finished      = pyqtSignal(int)
    error         = pyqtSignal(str)

    def __init__(self, source: str, allowed_exts: set):
        super().__init__()
        self.source       = source
        self.allowed_exts = allowed_exts
        self._stop        = False
        self.found_count  = 0

    def stop(self):
        self._stop = True

    def run(self):
        try:
            # Normalise to native backslash form — MSYS2 Python can silently
            # convert \\.\.X: to /X:, which pytsk3 cannot open on Windows.
            if IS_WINDOWS:
                self.source = self.source.replace("/", "\\")
            self.progress.emit(0, "Opening disk image / partition …")
            img = pytsk3.Img_Info(self.source)
            try:
                fs  = pytsk3.FS_Info(img)
                self.progress.emit(10, "File system opened — scanning …")
                self._walk_directory(fs, fs.open_dir(path="/"), "/")
            except Exception as e:
                print(f"DEBUG: Failed to open raw file system directly: {e}")
                self.progress.emit(5, f"Trying partition table … ({e})")
                self._scan_partitions(img)
        except Exception as e:
            if IS_WINDOWS:
                tip = (
                    "Tip: Ensure you ran your terminal/IDE as an Administrator.\n"
                    "Git Bash users: use the 'Git Bash Path' card on Step 1 to convert\n"
                    "paths like /c/image.dd → C:\\image.dd before scanning."
                )
            else:
                tip = "Tip: Run with sudo privileges."
            self.error.emit(f"Cannot open target source structure:\n{e}\n\n{tip}")
        finally:
            self.finished.emit(self.found_count)

    def _scan_partitions(self, img):
        try:
            vol = pytsk3.Volume_Info(img)
            parts = list(vol)
        except Exception as e:
            self.error.emit(f"Cannot read partition table: {e}")
            return
        for i, part in enumerate(parts):
            if self._stop:
                break
            if part.flags != pytsk3.TSK_VS_PART_FLAG_ALLOC:
                continue
            try:
                fs = pytsk3.FS_Info(img, offset=part.start * 512)
                self.progress.emit(10 + i * 5, f"Scanning partition {i+1} …")
                self._walk_directory(fs, fs.open_dir(path="/"), f"/part{i+1}")
            except Exception:
                continue

    def _walk_directory(self, fs, directory, path, depth=0):
        if self._stop or depth > 30:
            return
        for entry in directory:
            if self._stop:
                break
            try:
                name = entry.info.name.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue

                is_deleted = (
                    entry.info.meta is not None and
                    entry.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC
                )

                meta = entry.info.meta
                if meta and meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                    try:
                        sub = entry.as_directory()
                        self._walk_directory(fs, sub, f"{path}/{name}", depth + 1)
                    except Exception:
                        pass
                elif is_deleted:
                    ext = Path(name).suffix.lower()
                    if not self.allowed_exts or ext in self.allowed_exts:
                        size = meta.size if meta else 0
                        mtime = (datetime.datetime.fromtimestamp(meta.mtime).strftime("%Y-%m-%d %H:%M")
                                 if meta and meta.mtime else "Unknown")
                        self.found_count += 1
                        info = {
                            "name":    name,
                            "path":    f"{path}/{name}",
                            "size":    size,
                            "ext":     ext,
                            "mtime":   mtime,
                            "fs":      fs,
                            "inode":   meta.addr if meta else None,
                        }
                        self.file_found.emit(info)
                        self.progress.emit(
                            min(90, 10 + self.found_count % 80),
                            f"Found {self.found_count} deleted file(s) …"
                        )
            except Exception:
                continue


class RecoverWorker(QThread):
    progress   = pyqtSignal(int, str)
    finished   = pyqtSignal(int, int)
    error      = pyqtSignal(str)

    def __init__(self, files: list, dest: str, source: str):
        super().__init__()
        self.files  = files
        self.dest   = dest
        self.source = source

    def run(self):
        success = failed = 0
        try:
            img = pytsk3.Img_Info(self.source)
            fs  = None
            try:
                fs = pytsk3.FS_Info(img)
            except Exception:
                pass

            for i, finfo in enumerate(self.files):
                pct = int((i / len(self.files)) * 100)
                self.progress.emit(pct, f"Recovering {finfo['name']} …")
                try:
                    out_path = os.path.join(self.dest, finfo["name"])
                    base, ext2 = os.path.splitext(out_path)
                    counter = 1
                    while os.path.exists(out_path):
                        out_path = f"{base}_{counter}{ext2}"
                        counter += 1

                    if fs and finfo.get("inode"):
                        f_entry = fs.open_meta(inode=finfo["inode"])
                        size = finfo["size"]
                        CHUNK = 1024 * 1024
                        offset = 0
                        with open(out_path, "wb") as out:
                            while offset < size:
                                to_read = min(CHUNK, size - offset)
                                data = f_entry.read_random(offset, to_read)
                                if not data:
                                    break
                                out.write(data)
                                offset += len(data)
                        success += 1
                    else:
                        failed += 1
                except Exception:
                    failed += 1

        except Exception as e:
            self.error.emit(str(e))

        self.finished.emit(success, failed)


# ─── Carving Worker (Signature-Based) ─────────────────────────────────────────

class CarvingWorker(QThread):
    """
    Signature-based file carving engine adapted from the FileRecoveryTool article.
    Reads the source path block-by-block looking for known file magic bytes,
    then extracts each match to a temporary folder and emits file_found signals
    so the GUI can display results just like the TSK ScanWorker does.
    """
    progress   = pyqtSignal(int, str)
    file_found = pyqtSignal(dict)
    finished   = pyqtSignal(int)
    error      = pyqtSignal(str)

    BLOCK_SIZE = 512

    def __init__(self, source: str, allowed_exts: set, output_dir: str):
        super().__init__()
        self.source       = source
        # Map allowed_exts (like {'.jpg', '.pdf'}) to carving keys (like {'jpg', 'pdf'})
        if allowed_exts:
            self.file_types = [
                ft for ft in FILE_SIGNATURES
                if ('.' + ft) in allowed_exts or ft in allowed_exts
            ]
        else:
            self.file_types = list(FILE_SIGNATURES.keys())
        self.output_dir   = Path(output_dir)
        self._stop        = False
        self.found_count  = 0

    def stop(self):
        self._stop = True

    # Windows sector size — reads MUST be a multiple of this for raw devices
    WIN_SECTOR = 512

    def run(self):
        try:
            for ft in self.file_types:
                (self.output_dir / ft).mkdir(parents=True, exist_ok=True)

            # Normalise to native Windows backslash form (MSYS2-safe)
            if IS_WINDOWS:
                self.source = self.source.replace("/", "\\")
                import re as _re
                if _re.match(r'^[A-Za-z]:$', self.source):
                    self.source = f"\\\\.\\{self.source}"

            if IS_WINDOWS:
                self._run_windows()
            elif IS_WINDOWS and len(self.source) >= 2 and self.source[1] == ':':
                # Bare drive path like C:\Users\... — wrap as device
                self._run_windows()
            else:
                device_size = self._get_device_size_posix()
                self.progress.emit(0, f"Carving {_human(device_size)} of raw data …")
                with open(self.source, 'rb', buffering=0) as dev:
                    self._scan(dev, device_size)

        except (IOError, OSError) as exc:
            if IS_WINDOWS:
                tip = (
                    "Run as Administrator.\n"
                    "Git Bash users: use the 'Git Bash Path' card on Step 1 — paths like\n"
                    "/c/image.dd are auto-converted to C:\\image.dd."
                )
            else:
                tip = "Try: sudo python3 …"
            self.error.emit(f"Cannot open source for carving:\n{exc}\n\n{tip}")
        finally:
            self.finished.emit(self.found_count)

    # ── Windows raw-device path ───────────────────────────────────────────────

    def _run_windows(self):
        """
        Open a Windows raw device (e.g. \\\\.\\D: or \\\\.\\PhysicalDriveN) using
        CreateFile with FILE_FLAG_NO_BUFFERING so that seek/read are
        sector-aligned.  msvcrt.open_osfhandle wraps the handle as a
        normal Python file object.
        """
        import ctypes
        import ctypes.wintypes
        import msvcrt

        GENERIC_READ             = 0x80000000
        FILE_SHARE_READ          = 0x00000001
        FILE_SHARE_WRITE         = 0x00000002
        OPEN_EXISTING            = 3
        FILE_FLAG_NO_BUFFERING   = 0x20000000
        FILE_FLAG_SEQUENTIAL_SCAN= 0x08000000
        INVALID_HANDLE_VALUE     = ctypes.wintypes.HANDLE(-1).value

        kernel32 = ctypes.windll.kernel32

        handle = kernel32.CreateFileW(
            self.source,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if handle == INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise OSError(
                f"CreateFile failed on '{self.source}' "
                f"(Windows error {err}). Run as Administrator."
            )

        try:
            device_size = self._get_device_size_windows(handle, kernel32)
            self.progress.emit(0, f"Carving {_human(device_size)} of raw data …")

            # Wrap the Win32 handle as a Python file descriptor
            fd  = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None          # ownership transferred — don't close twice
            with os.fdopen(fd, 'rb', buffering=0) as dev:
                self._scan_windows(dev, device_size)
        finally:
            if handle is not None:
                kernel32.CloseHandle(handle)

    def _get_device_size_windows(self, handle, kernel32) -> int:
        """Query disk geometry via IOCTL_DISK_GET_DRIVE_GEOMETRY_EX (0x000700A0)."""
        import ctypes
        # DISK_GEOMETRY_EX is at least 24 bytes; use 256 to be safe
        buf  = ctypes.create_string_buffer(256)
        ret  = ctypes.wintypes.DWORD(0)
        ok   = kernel32.DeviceIoControl(
            handle,
            0x000700A0,          # IOCTL_DISK_GET_DRIVE_GEOMETRY_EX
            None, 0,
            buf, ctypes.sizeof(buf),
            ctypes.byref(ret),
            None,
        )
        if ok:
            # DiskSize is a LARGE_INTEGER at offset 24 in DISK_GEOMETRY_EX
            import struct as _struct
            try:
                size = _struct.unpack_from('<q', buf, 24)[0]
                if size > 0:
                    return size
            except Exception:
                pass
        # Fallback: seek to end
        try:
            LARGE_INTEGER = ctypes.c_int64
            dist   = LARGE_INTEGER(0)
            newpos = LARGE_INTEGER(0)
            kernel32.SetFilePointerEx(handle, dist, ctypes.byref(newpos), 2)  # FILE_END
            size = newpos.value
            kernel32.SetFilePointerEx(handle, dist, ctypes.byref(newpos), 0)  # FILE_BEGIN
            if size > 0:
                return size
        except Exception:
            pass
        return 32 * 1024 * 1024 * 1024  # 32 GB safe fallback

    def _scan_windows(self, dev, device_size: int):
        """
        Like _scan() but reads must be sector-aligned (multiples of WIN_SECTOR).
        We use a larger read_size so each iteration covers many sectors.
        """
        READ_SIZE = 65536   # 128 × 512 — must be multiple of WIN_SECTOR
        position  = 0
        while position < device_size and not self._stop:
            to_read = min(READ_SIZE, device_size - position)
            # Align up to sector boundary
            to_read = ((to_read + self.WIN_SECTOR - 1) // self.WIN_SECTOR) * self.WIN_SECTOR
            try:
                data = dev.read(to_read)
            except OSError:
                position += READ_SIZE
                continue
            if not data:
                break

            self._search_block(dev, data, position, device_size)
            position += len(data)

            pct = min(90, int(position * 90 / device_size)) if device_size else 0
            if position % (20 * 1024 * 1024) == 0:
                self.progress.emit(
                    pct,
                    f"Carved {self.found_count} file(s) — {_human(position)} scanned …"
                )

    # ── POSIX / image-file path ───────────────────────────────────────────────

    def _get_device_size_posix(self) -> int:
        if os.path.isfile(self.source):
            return os.path.getsize(self.source)
        try:
            result = subprocess.run(
                ['blockdev', '--getsize64', self.source],
                capture_output=True, text=True, check=True
            )
            return int(result.stdout.strip())
        except Exception:
            pass
        try:
            with open(self.source, 'rb') as fd:
                fd.seek(0, 2)
                return fd.tell()
        except Exception:
            return 1024 * 1024 * 1024  # 1 GB fallback

    def _scan(self, dev, device_size: int):
        """POSIX / image-file scan: arbitrary seek + read."""
        READ_SIZE = 65536
        position  = 0
        while position < device_size and not self._stop:
            dev.seek(position)
            data = dev.read(READ_SIZE)
            if not data:
                break

            self._search_block(dev, data, position, device_size)
            position += len(data)

            pct = min(90, int(position * 90 / device_size)) if device_size else 0
            if position % (20 * 1024 * 1024) == 0:
                self.progress.emit(
                    pct,
                    f"Carved {self.found_count} file(s) — {_human(position)} scanned …"
                )

    def _search_block(self, dev, data: bytes, block_start: int, device_size: int):
        """Search one buffer for all file signatures and carve matches."""
        for ft in self.file_types:
            if self._stop:
                return
            for sig in FILE_SIGNATURES.get(ft, []):
                offset = 0
                while True:
                    sig_pos = data.find(sig, offset)
                    if sig_pos == -1:
                        break
                    abs_pos = block_start + sig_pos
                    dev.seek(abs_pos)
                    file_data = self._extract_file(dev, ft)
                    if file_data:
                        self._emit_carved_file(ft, abs_pos, file_data)
                    offset = sig_pos + 1

    def _extract_file(self, dev, ft: str) -> bytes | None:
        max_size = MAX_FILE_SIZES.get(ft, 10 * 1024 * 1024)
        trailer  = FILE_TRAILERS.get(ft)
        if trailer:
            return self._read_until_trailer(dev, trailer, max_size)
        return self._read_heuristic(dev, ft, max_size)

    def _read_until_trailer(self, dev, trailer: bytes, max_size: int) -> bytes | None:
        buf = bytearray()
        chunk = 4096
        while len(buf) < max_size:
            piece = dev.read(chunk)
            if not piece:
                break
            buf.extend(piece)
            pos = buf.find(trailer, max(0, len(buf) - len(trailer) - chunk))
            if pos != -1:
                return bytes(buf[:pos + len(trailer)])
        return bytes(buf) if len(buf) >= 100 else None

    def _read_heuristic(self, dev, ft: str, max_size: int) -> bytes | None:
        buf        = bytearray()
        chunk_size = 4096
        init_size  = 16384 if ft in ('docx', 'xlsx', 'pptx', 'zip') else chunk_size
        init       = dev.read(init_size)
        if not init:
            return None
        buf.extend(init)

        # Early structural validation for Office/ZIP formats
        checks = {'docx': b'word/', 'xlsx': b'xl/', 'pptx': b'ppt/', 'zip': b'PK\x01\x02'}
        if ft in checks and checks[ft] not in init:
            return None

        invalid = 0
        while len(buf) < max_size:
            piece = dev.read(chunk_size)
            if not piece:
                break
            buf.extend(piece)
            if ft in ('zip', 'docx', 'xlsx', 'pptx') and b'PK' not in piece and len(buf) > 10 * chunk_size:
                invalid += 1
            elif ft not in ('jpg', 'png', 'gif', 'pdf', 'mp3', 'mp4', 'avi', 'zip', 'docx', 'xlsx', 'pptx'):
                ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in piece) / len(piece)
                invalid += 0 if ratio >= 0.7 else 1
            if invalid > 3:
                trim = len(buf) - invalid * chunk_size
                return bytes(buf[:max(0, trim)]) if trim >= 100 else None
        return bytes(buf) if len(buf) >= 100 else None

    def _validate(self, data: bytes, ft: str) -> bool:
        if len(data) < 100:
            return False
        patterns = VALIDATION_PATTERNS.get(ft, [])
        if patterns:
            return any(p in data for p in patterns)
        return True

    def _emit_carved_file(self, ft: str, position: int, data: bytes):
        if not self._validate(data, ft):
            return
        uid      = binascii.hexlify(os.urandom(3)).decode()
        filename = f"carved_{ft}_{position}_{uid}.{ft}"
        out_path = self.output_dir / ft / filename
        try:
            with open(out_path, 'wb') as f:
                f.write(data)
        except OSError:
            return

        self.found_count += 1
        info = {
            "name":   filename,
            "path":   str(out_path),
            "size":   len(data),
            "ext":    '.' + ft,
            "mtime":  datetime.now().strftime("%Y-%m-%d %H:%M"),
            "fs":     None,
            "inode":  None,
            # Carving mode stores the actual recovered bytes on disk already
            "carved_path": str(out_path),
        }
        self.file_found.emit(info)
        self.progress.emit(
            min(90, 10 + self.found_count % 80),
            f"Carved {self.found_count} file(s) …"
        )


# ─── Raw Sector Scan: Full Signature Table (adapted from recov3.py v2) ────────
# A much wider signature set than the carving engine's FILE_SIGNATURES table,
# including "container bait" signatures (RIFF, ZIP, ISO-media ftyp boxes) that
# need a second pass to disambiguate into a concrete format.

RAW_SIGNATURES = {
    # --- IMAGES ---
    b"\xFF\xD8\xFF": "JPG/JPEG",
    b"\x89PNG\r\n\x1a\n": "PNG",
    b"GIF87a": "GIF",
    b"GIF89a": "GIF",
    b"BM": "BMP",
    b"II*\x00": "TIFF",
    b"MM\x00*": "TIFF",
    b"8BPS": "PSD",
    b"<?xml": "SVG",
    b"\x49\x49\x2a\x00\x10\x00\x00\x00": "CR2",
    b"\x4d\x4d\x00\x2a": "NEF",

    # --- AUDIO & VIDEO CONTAINER BAIT ---
    b"RIFF": "RIFF_CONTAINER",   # Dissected downstream for WAV, AVI, WEBP
    b"OggS": "OGG/OPUS",
    b"fLaC": "FLAC",
    b"ID3": "MP3",
    b"\xFF\xFB": "MP3",
    b"\xFF\xF1": "AAC",
    b"\xFF\xF9": "AAC",

    # --- VIDEO & AUDIO (ISO BASE MEDIA CONTAINERS) ---
    b"\x1a\x45\xdf\xa3": "MKV/WEBM",
    b"FLV\x01": "FLV",
    b"\x00\x00\x01\xBA": "MPEG",
    b"\x00\x00\x01\xB3": "MPG",
    b"\x30\x26\xB2\x75\x8E\x66\xCF\x11": "WMV/WMA",

    # --- DOCUMENTS & ARCHIVES ---
    b"%PDF": "PDF",
    b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1": "DOC/XLS/PPT",   # Legacy Microsoft Binary
    b"PK\x03\x04": "ZIP_CONTAINER",                       # Deep parsed for modern formats
    b"Rar!\x1a\x07\x00": "RAR",
    b"Rar!\x1a\x07\x01\x00": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7Z",
    b"\x1f\x8b": "GZ",
    b"BZh": "BZ2",
    b"\xfd\x37\x7a\x58\x5a\x00": "XZ",

    # --- TEXT / SOURCE CODE ---
    b"#!/": "SHELL_SCRIPT",
    b"import ": "PYTHON",
    b"def ": "PYTHON",
    b"#include": "C/CPP",
    b"using namespace": "CPP",
    b"<!DOCTYPE html": "HTML",
    b"<html>": "HTML",
}

# Final (post-disambiguation) type label -> candidate extensions, in priority
# order. The first candidate is the default; if the user's selection includes
# one of the alternates (e.g. "webm" instead of "mkv") that one is used for
# the saved filename instead.
RAW_TYPE_EXTS = {
    "JPG/JPEG":     ("jpg", "jpeg"),
    "PNG":          ("png",),
    "GIF":          ("gif",),
    "BMP":          ("bmp",),
    "TIFF":         ("tiff", "tif"),
    "PSD":          ("psd",),
    "SVG":          ("svg",),
    "CR2":          ("cr2",),
    "NEF":          ("nef",),
    "WAV":          ("wav",),
    "AVI":          ("avi",),
    "WEBP":         ("webp",),
    "OGG/OPUS":     ("ogg", "opus"),
    "FLAC":         ("flac",),
    "MP3":          ("mp3",),
    "AAC":          ("aac",),
    "MKV/WEBM":     ("mkv", "webm"),
    "FLV":          ("flv",),
    "MPEG":         ("mpeg",),
    "MPG":          ("mpg",),
    "WMV/WMA":      ("wmv", "wma"),
    "PDF":          ("pdf",),
    "DOC/XLS/PPT":  ("doc", "xls", "ppt"),
    "ZIP":          ("zip",),
    "DOCX":         ("docx",),
    "XLSX":         ("xlsx",),
    "PPTX":         ("pptx",),
    "ODT":          ("odt",),
    "ODS":          ("ods",),
    "ODP":          ("odp",),
    "RAR":          ("rar",),
    "7Z":           ("7z",),
    "GZ":           ("gz",),
    "BZ2":          ("bz2",),
    "XZ":           ("xz",),
    "SHELL_SCRIPT": ("sh",),
    "PYTHON":       ("py",),
    "C/CPP":        ("c", "cpp"),
    "CPP":          ("cpp",),
    "HTML":         ("html",),
    "MP4":          ("mp4",),
    "M4V":          ("m4v",),
    "M4A":          ("m4a",),
    "MOV":          ("mov",),
    "HEIC":         ("heic",),
    "3GP":          ("3gp",),
    "JSON":         ("json",),
    # Ambiguous/undecodable container results — never saved.
    "RIFF_DATA":         (),
    "ISO_MEDIA_FORMAT":  (),
}

# Flattened "any extension Raw Sector Mode can actually produce" — drives
# which checkboxes are shown in Step 2 when Raw Sector Mode is selected.
RAW_SUPPORTED_EXTS = {
    "." + ext
    for exts in RAW_TYPE_EXTS.values()
    for ext in exts
}


def _parse_raw_container(sector_data: bytes, primary_type: str) -> str:
    """Deep-inspect bytes to distinguish overlapping structural formats
    (ISO media boxes, RIFF wrappers, ZIP-based Office/OpenDocument formats)."""
    # ISO Base Media File Format (MP4, MOV, HEIC, M4V, 3GP, M4A)
    if b"ftyp" in sector_data[4:12]:
        box = sector_data[8:16]
        if b"mp4" in box or b"MSNV" in box:
            return "MP4"
        if b"m4v" in box:
            return "M4V"
        if b"M4A" in box:
            return "M4A"
        if b"qt  " in box:
            return "MOV"
        if b"heic" in box or b"mif1" in box:
            return "HEIC"
        if b"3gp" in box:
            return "3GP"
        return "ISO_MEDIA_FORMAT"

    if primary_type == "RIFF_CONTAINER":
        payload = sector_data[8:12]
        if payload == b"WAVE":
            return "WAV"
        if payload == b"AVI ":
            return "AVI"
        if payload == b"WEBP":
            return "WEBP"
        return "RIFF_DATA"

    if primary_type == "ZIP_CONTAINER":
        if b"word/" in sector_data:
            return "DOCX"
        if b"xl/" in sector_data:
            return "XLSX"
        if b"ppt/" in sector_data:
            return "PPTX"
        if b"document" in sector_data and b"oasis" in sector_data:
            return "ODT"
        if b"spreadsheet" in sector_data and b"oasis" in sector_data:
            return "ODS"
        if b"presentation" in sector_data and b"oasis" in sector_data:
            return "ODP"
        return "ZIP"

    return primary_type


class RawSectorScanWorker(QThread):
    """
    Lightweight raw sector scanner, adapted from the standalone recov3.py
    script (full-signature version). Unlike CarvingWorker (which slides
    byte-by-byte through each read buffer looking for a signature anywhere),
    this reads the source in fixed SECTOR_SIZE chunks and only counts a hit
    when a signature sits at the very START of a sector. That makes it much
    faster and simpler, at the cost of missing any signature that happens to
    start mid-sector. Container "bait" signatures (RIFF/ZIP/ftyp) are deep
    -inspected to resolve the concrete format (e.g. WAV vs AVI vs WEBP).

    Good fit for a quick first pass on a raw logical volume / image before
    falling back to full TSK or carving scans.
    """
    progress   = pyqtSignal(int, str)
    stats      = pyqtSignal(int, int)   # (current_sector, total_sectors)
    file_found = pyqtSignal(dict)
    finished   = pyqtSignal(int)
    error      = pyqtSignal(str)

    SECTOR_SIZE = 512

    def __init__(self, source: str, allowed_exts: set, output_dir: str, sector_size: int = SECTOR_SIZE):
        super().__init__()
        self.source       = source
        self.output_dir   = Path(output_dir)
        self.sector_size  = sector_size
        self._stop        = False
        self.found_count  = 0
        # Normalise to a bare, dot-less, lowercase set for easy lookup
        self.allowed_exts = {e.lstrip(".").lower() for e in (allowed_exts or set())}

        # Sort root signatures longest-first so a more specific match (e.g.
        # an 8-byte WMV/WMA signature) is checked before a shorter generic one.
        self._signatures = dict(
            sorted(RAW_SIGNATURES.items(), key=lambda kv: -len(kv[0]))
        )

    def stop(self):
        self._stop = True

    def run(self):
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
            if IS_WINDOWS:
                self.source = self.source.replace("/", "\\")

            device_size = self._get_device_size()
            self.progress.emit(0, f"Raw sector scan of {_human(device_size)} …")

            total_sectors = device_size // self.sector_size if device_size else 0
            # Emit totals immediately so the banner can show "X / total" from the start
            self.stats.emit(0, total_sectors)

            with open(self.source, "rb") as disk:
                sector_number = 0
                while not self._stop:
                    sector_data = disk.read(self.sector_size)
                    if not sector_data:
                        self.progress.emit(100, "Scan complete.")
                        self.stats.emit(sector_number, total_sectors)
                        break
                    if len(sector_data) < self.sector_size:
                        break

                    self._evaluate_sector(disk, sector_data, sector_number)

                    sector_number += 1
                    # Emit stats every 100 sectors for smooth live updates
                    # (every single sector on a 2TB drive = billions of signals → UI freeze)
                    if sector_number % 100 == 0:
                        self.stats.emit(sector_number, total_sectors)
                        # Progress bar: percentage based on bytes scanned / total bytes
                        if total_sectors > 0:
                            pct = min(99, int(sector_number * 100 / total_sectors))
                        else:
                            pct = 0
                        self.progress.emit(
                            pct,
                            f"Scanning … {self.found_count} file(s) found"
                        )
        except PermissionError:
            tip = "Run your terminal/IDE as Administrator." if IS_WINDOWS else "Try: sudo python3 …"
            self.error.emit(f"Access denied opening '{self.source}'.\n\n{tip}")
        except FileNotFoundError:
            self.error.emit(f"Target path unavailable: {self.source}")
        except Exception as e:
            self.error.emit(f"Raw sector scan failed:\n{e}")
        finally:
            self.finished.emit(self.found_count)

    def _get_device_size(self) -> int:
        """
        Return the byte size of the source.
        - Regular files: os.path.getsize()
        - Linux/macOS block devices: seek(0, 2)
        - Windows raw volumes (\\\\.\\X:, \\\\.\\PhysicalDriveN):
            seek(0,2) always returns 0, so we use DeviceIoControl
            IOCTL_DISK_GET_LENGTH_INFO (0x7405C) instead.
        """
        try:
            if os.path.isfile(self.source):
                return os.path.getsize(self.source)
        except Exception:
            pass

        if IS_WINDOWS and self.source.startswith("\\\\.\\"):
            try:
                import ctypes, ctypes.wintypes
                GENERIC_READ      = 0x80000000
                FILE_SHARE_READ   = 0x00000001
                FILE_SHARE_WRITE  = 0x00000002
                OPEN_EXISTING     = 3
                IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C

                h = ctypes.windll.kernel32.CreateFileW(
                    self.source,
                    GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    None, OPEN_EXISTING, 0, None
                )
                INVALID_HANDLE = ctypes.c_void_p(-1).value
                if h != INVALID_HANDLE:
                    length = ctypes.c_int64(0)
                    bytes_ret = ctypes.wintypes.DWORD(0)
                    ok = ctypes.windll.kernel32.DeviceIoControl(
                        h, IOCTL_DISK_GET_LENGTH_INFO,
                        None, 0,
                        ctypes.byref(length), ctypes.sizeof(length),
                        ctypes.byref(bytes_ret), None
                    )
                    ctypes.windll.kernel32.CloseHandle(h)
                    if ok and length.value > 0:
                        return length.value
            except Exception:
                pass

        # Fallback: try psutil for the mountpoint matching this device
        try:
            import re as _re_ds
            m = _re_ds.search(r'([A-Za-z]):', self.source)
            if m:
                letter = m.group(1).upper()
                usage = psutil.disk_usage(letter + ":\\")
                if usage.total > 0:
                    return usage.total
        except Exception:
            pass

        # Last resort: seek — works on Linux block devices
        try:
            with open(self.source, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size > 0:
                    return size
        except Exception:
            pass

        return 0

    def _evaluate_sector(self, disk, sector_data: bytes, sector_number: int):
        # Catch plaintext JSON, which has no fixed magic bytes.
        # Route through _save_hit so allowed_exts filtering is applied.
        if sector_data[:1] == b"{" and b":" in sector_data:
            self._save_hit(disk, "JSON", sector_number)
            # Don't return early — but if JSON was accepted, we're done.
            # If _save_hit filtered it out (not in allowed_exts), continue
            # checking signatures below in case a binary sig also matches.
            # Actually: JSON starting with '{' won't match any binary sig,
            # so we can safely return here regardless.
            return

        for signature, primary_type in self._signatures.items():
            if sector_data.startswith(signature):
                final_type = _parse_raw_container(sector_data, primary_type)
                self._save_hit(disk, final_type, sector_number)
                return

        # Root signature missed but the sector still looks like an
        # ISO-media box (ftyp may not sit at offset 0 within the sector).
        if b"ftyp" in sector_data[4:12]:
            final_type = _parse_raw_container(sector_data, "FTYP_BAIT")
            self._save_hit(disk, final_type, sector_number)

    def _save_hit(self, disk, final_type: str, sector_number: int):
        candidates = RAW_TYPE_EXTS.get(final_type, ())
        if not candidates:
            return   # Ambiguous container with no concrete format — skip.

        # Pick whichever candidate extension the user actually selected;
        # default to the first candidate when nothing is selected (treat
        # an empty selection like CarvingWorker does — accept everything).
        ext = None
        if self.allowed_exts:
            ext = next((c for c in candidates if c in self.allowed_exts), None)
            if ext is None:
                return   # User didn't ask for any of this type's extensions.
        else:
            ext = candidates[0]

        abs_pos    = sector_number * self.sector_size
        resume_pos = abs_pos + self.sector_size
        data = None
        try:
            disk.seek(abs_pos)
            trailer  = FILE_TRAILERS.get(ext)
            max_size = MAX_FILE_SIZES.get(ext, 10 * 1024 * 1024)
            if trailer:
                data = self._read_until_trailer(disk, trailer, max_size)
            elif ext in ("zip", "docx", "xlsx", "pptx", "odt", "ods", "odp"):
                data = self._read_heuristic(disk, ext, max_size)
            else:
                # No trailer and no zip-style heuristic available (text/code
                # files, exotic image formats, etc.) — grab a bounded chunk.
                cap = min(max_size, 2 * 1024 * 1024)
                data = disk.read(cap)
        except Exception:
            data = None
        finally:
            try:
                disk.seek(resume_pos)
            except Exception:
                pass

        if not data or len(data) < 16:
            return

        uid      = binascii.hexlify(os.urandom(3)).decode()
        filename = f"rawscan_{ext}_{abs_pos}_{uid}.{ext}"
        out_path = self.output_dir / filename
        try:
            with open(out_path, "wb") as f:
                f.write(data)
        except OSError:
            return

        self.found_count += 1
        info = {
            "name":   filename,
            "path":   str(out_path),
            "size":   len(data),
            "ext":    "." + ext,
            "mtime":  datetime.now().strftime("%Y-%m-%d %H:%M"),
            "fs":     None,
            "inode":  None,
            # Like carving mode, the bytes are already written to disk.
            "carved_path": str(out_path),
        }
        self.file_found.emit(info)
        self.progress.emit(
            min(90, 10 + self.found_count % 80),
            f"Found {self.found_count} file(s) — sector {sector_number} ({final_type}) …"
        )

    def _read_until_trailer(self, dev, trailer: bytes, max_size: int):
        buf = bytearray()
        chunk = 4096
        while len(buf) < max_size:
            piece = dev.read(chunk)
            if not piece:
                break
            buf.extend(piece)
            pos = buf.find(trailer, max(0, len(buf) - len(trailer) - chunk))
            if pos != -1:
                return bytes(buf[:pos + len(trailer)])
        return bytes(buf) if len(buf) >= 100 else None

    def _read_heuristic(self, dev, ext: str, max_size: int):
        """For ZIP-based formats with no fixed trailer — validate early
        structure, then keep reading until data quality drops or we hit
        the size cap (same approach CarvingWorker uses)."""
        buf        = bytearray()
        chunk_size = 4096
        init_size  = 16384
        init       = dev.read(init_size)
        if not init:
            return None
        buf.extend(init)

        checks = {"docx": b"word/", "xlsx": b"xl/", "pptx": b"ppt/", "zip": b"PK\x01\x02"}
        if ext in checks and checks[ext] not in init:
            return None

        invalid = 0
        while len(buf) < max_size:
            piece = dev.read(chunk_size)
            if not piece:
                break
            buf.extend(piece)
            if b"PK" not in piece and len(buf) > 10 * chunk_size:
                invalid += 1
            if invalid > 3:
                trim = len(buf) - invalid * chunk_size
                return bytes(buf[:max(0, trim)]) if trim >= 100 else None
        return bytes(buf) if len(buf) >= 100 else None

# ─── Drive Card Widget ────────────────────────────────────────────────────────

class DriveCard(QFrame):
    clicked = pyqtSignal(object)

    BAR_NORMAL = "#2e7dcc"
    BAR_LOST   = "#e74c3c"

    def __init__(self, drive_info: dict, parent=None):
        super().__init__(parent)
        self.drive_info = drive_info
        self._selected  = False
        self._lost      = drive_info.get("lost", False)

        obj = "driveCardLost" if self._lost else "driveCard"
        self.setObjectName(obj)
        card_height = 130 if IS_GIT_BASH else 110
        self.setFixedSize(170, card_height)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(4)

        top = QHBoxLayout()
        top.setSpacing(8)
        icon_lbl = QLabel(self._icon())
        icon_lbl.setObjectName("cardIcon")
        icon_lbl.setFixedWidth(32)
        top.addWidget(icon_lbl)

        name_lbl = QLabel(drive_info["label"])
        name_lbl.setObjectName("cardName")
        name_lbl.setWordWrap(True)
        name_lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        top.addWidget(name_lbl, 1)
        layout.addLayout(top)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(5)
        pct = self._usage_pct()
        self.bar.setValue(pct)
        bar_colour = self.BAR_LOST if self._lost else self.BAR_NORMAL
        self.bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: #2a2d38;
                border-radius: 2px;
                border: none;
            }}
            QProgressBar::chunk {{
                background-color: {bar_colour};
                border-radius: 2px;
            }}
        """)
        layout.addWidget(self.bar)

        size_bytes = drive_info.get("size_bytes", 0)
        used_bytes = drive_info.get("used_bytes", 0)
        if size_bytes:
            size_text = f"{_human(used_bytes)} / {_human(size_bytes)}"
        else:
            size_text = drive_info.get("drive_type", "").capitalize()
        size_lbl = QLabel(size_text)
        size_lbl.setObjectName("cardSize")
        layout.addWidget(size_lbl)

        # Git Bash path badge — shown only when Git Bash environment is active
        if IS_GIT_BASH:
            gb_path = drive_info.get("gitbash_path", "")
            gb_lbl = QLabel(f"🐚 {gb_path}" if gb_path else "")
            gb_lbl.setStyleSheet(
                "color: #5dade2; font-size: 10px; font-family: monospace;"
                "background: #1a2535; border-radius: 3px; padding: 1px 4px;"
            )
            gb_lbl.setToolTip(
                f"Git Bash path: {gb_path}\n"
                "This is how Git Bash / MSYS2 sees this drive.\n"
                "Clicking the card uses the native Windows device path for scanning."
            )
            layout.addWidget(gb_lbl)

    def _icon(self) -> str:
        if self._lost:
            return "⛔"
        dt = self.drive_info.get("drive_type", "")
        if dt == "physical":
            return "💾"
        label = self.drive_info.get("label", "").upper()
        if "C:" in label or "WINDOWS" in label or "SYSTEM" in label:
            return "🖥️"
        if any(x in label for x in ["VIDEO", "VMS", "VM"]):
            return "🖴"
        if any(x in label for x in ["STORAGE", "BACKUP", "ARCHIVE"]):
            return "🗄️"
        return "💿"

    def _usage_pct(self) -> int:
        size = self.drive_info.get("size_bytes", 0)
        used = self.drive_info.get("used_bytes", 0)
        if size and size > 0:
            return min(100, int(used * 100 / size))
        return 0 if not self._lost else 100

    def set_selected(self, selected: bool):
        self._selected = selected
        self.setProperty("selected", "true" if selected else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self)
        super().mousePressEvent(event)


class QuickAccessCard(QFrame):
    clicked = pyqtSignal(object)

    ITEMS = {
        "Disk Image":     "🗂️",
        "Git Bash Path":  "🐚",
        "Desktop":        "🖥️",
        "Select Folder":  "📁",
        "Recycle Bin":    "🗑️",
    }

    def __init__(self, name: str, parent=None):
        super().__init__(parent)
        self.name = name
        self._selected = False
        self.setObjectName("quickAccessCard")
        self.setFixedSize(150, 80)
        self.setCursor(Qt.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 8)
        layout.setSpacing(4)
        layout.setAlignment(Qt.AlignCenter)

        icon_lbl = QLabel(self.ITEMS.get(name, "📁"))
        icon_lbl.setObjectName("qaIcon")
        icon_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(icon_lbl)

        name_lbl = QLabel(name)
        name_lbl.setObjectName("qaName")
        name_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(name_lbl)

    def set_selected(self, s: bool):
        self._selected = s
        self.setProperty("selected", "true" if s else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self)
        super().mousePressEvent(event)


# ─── Main Window ──────────────────────────────────────────────────────────────

class FileRecoveryApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DiskRecovery Pro")
        self.setMinimumSize(1000, 700)
        self.resize(1100, 750)

        self.source_path    = ""
        self.dest_path      = ""
        self.found_files    = []
        self.scan_worker    = None
        self.carving_worker = None
        self.recover_worker = None
        self.scan_mode      = "tsk"        # "tsk" | "carving" | "raw"
        self._carving_dir   = os.path.join(tempfile.gettempdir(), "diskrecovery_carve")
        self._raw_dir       = os.path.join(tempfile.gettempdir(), "diskrecovery_rawscan")

        self._selected_drive_card = None
        self._drive_cards         = []
        self._qa_cards            = []
        self._drive_total_sectors = 0
        self._drive_sector_size   = 512
        self._drive_total_bytes   = 0

        self._build_ui()
        self.setStyleSheet(DARK_STYLE)
        self._go_to_step(1)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._make_header())
        root.addWidget(self._make_step_bar())

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        self.stack.addWidget(self._page_source())
        self.stack.addWidget(self._page_filetypes())
        self.stack.addWidget(self._page_results())
        self.stack.addWidget(self._page_recover())

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

    def _make_header(self):
        bar = QFrame()
        bar.setFixedHeight(52)
        bar.setStyleSheet("background-color:#13151b; border-bottom:1px solid #2a2d35;")
        h = QHBoxLayout(bar)
        h.setContentsMargins(20, 0, 20, 0)

        icon_lbl = QLabel("💿")
        icon_lbl.setFont(QFont("Arial", 20))
        title = QLabel("DiskRecovery Pro")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color:#2e7dcc;")

        sub = QLabel("Recover deleted files · TSK filesystem mode + Signature carving mode")
        sub.setStyleSheet("color:#666; font-size:12px;")

        h.addWidget(icon_lbl)
        h.addSpacing(8)
        h.addWidget(title)
        h.addSpacing(12)
        h.addWidget(sub)
        h.addStretch()

        env_label = f"{CURRENT_OS} · Git Bash" if IS_GIT_BASH else CURRENT_OS
        os_badge = QLabel(f"  {env_label}  ")
        os_badge.setStyleSheet(
            "background:#2a2d35; color:#888; border-radius:4px; font-size:11px; padding:2px 6px;"
        )
        h.addWidget(os_badge)
        return bar

    def _make_step_bar(self):
        bar = QFrame()
        bar.setFixedHeight(48)
        bar.setStyleSheet("background-color:#16181e; border-bottom:1px solid #2a2d35;")
        h = QHBoxLayout(bar)
        h.setContentsMargins(20, 0, 20, 0)
        h.setSpacing(0)

        steps = [
            ("1", "Select Source"),
            ("2", "File Types"),
            ("3", "Scan & Preview"),
            ("4", "Recover"),
        ]
        self._step_labels = []
        for i, (num, label) in enumerate(steps):
            if i:
                sep = QLabel("›")
                sep.setStyleSheet("color:#444; font-size:18px; padding:0 10px;")
                h.addWidget(sep)

            btn = QPushButton(f"  {num}. {label}  ")
            btn.setFlat(True)
            btn.setObjectName(f"step_{i+1}")
            btn.setCursor(Qt.PointingHandCursor)
            self._step_labels.append(btn)
            h.addWidget(btn)

        h.addStretch()
        return bar

    def _page_source(self):
        outer = QWidget()
        v = QVBoxLayout(outer)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("background: #13151b;")

        content = QWidget()
        content.setStyleSheet("background: #13151b;")
        cv = QVBoxLayout(content)
        cv.setContentsMargins(24, 20, 24, 16)
        cv.setSpacing(16)

        self._drives_section_label = QLabel("Detected Partitions(0)")
        self._drives_section_label.setObjectName("sectionHeader")
        cv.addWidget(self._drives_section_label)

        self._drives_grid_widget = QWidget()
        self._drives_grid_widget.setStyleSheet("background:transparent;")
        self._drives_grid = QGridLayout(self._drives_grid_widget)
        self._drives_grid.setSpacing(12)
        self._drives_grid.setContentsMargins(0, 0, 0, 0)
        cv.addWidget(self._drives_grid_widget)

        self._ext_section_label = QLabel("External Drives(0)")
        self._ext_section_label.setObjectName("sectionHeader")
        cv.addWidget(self._ext_section_label)

        self._ext_grid_widget = QWidget()
        self._ext_grid_widget.setStyleSheet("background:transparent;")
        self._ext_grid = QGridLayout(self._ext_grid_widget)
        self._ext_grid.setSpacing(12)
        self._ext_grid.setContentsMargins(0, 0, 0, 0)
        cv.addWidget(self._ext_grid_widget)

        qa_label = QLabel("Quick Access(5)")
        qa_label.setObjectName("sectionHeader")
        cv.addWidget(qa_label)

        qa_row = QHBoxLayout()
        qa_row.setSpacing(12)
        qa_row.setContentsMargins(0, 0, 0, 0)
        for name in ["Disk Image", "Git Bash Path", "Desktop", "Select Folder", "Recycle Bin"]:
            card = QuickAccessCard(name)
            card.clicked.connect(self._on_qa_card_clicked)
            self._qa_cards.append(card)
            qa_row.addWidget(card)
        qa_row.addStretch()
        cv.addLayout(qa_row)

        cv.addStretch()

        scroll.setWidget(content)
        v.addWidget(scroll, 1)

        bottom = QFrame()
        bottom.setFixedHeight(62)
        bottom.setStyleSheet("background:#16181e; border-top:1px solid #2a2d35;")
        bh = QHBoxLayout(bottom)
        bh.setContentsMargins(20, 8, 20, 8)

        self._selected_path_lbl = QLabel("No source selected")
        self._selected_path_lbl.setStyleSheet("color:#666; font-size:12px;")
        bh.addWidget(self._selected_path_lbl, 1)

        if _is_admin():
            priv_lbl = QLabel("✅  Admin / root")
            priv_lbl.setStyleSheet("color:#27ae60; font-size:11px;")
        else:
            priv_lbl = QLabel("⚠  Not admin — device scan may fail")
            priv_lbl.setStyleSheet("color:#e67e22; font-size:11px;")
        bh.addWidget(priv_lbl)
        bh.addSpacing(16)

        btn_refresh = QPushButton("⟳  Refresh")
        btn_refresh.setFixedWidth(110)
        btn_refresh.clicked.connect(self._populate_devices)
        bh.addWidget(btn_refresh)

        btn_next = QPushButton("Next  →")
        btn_next.setObjectName("success")
        btn_next.setFixedWidth(130)
        btn_next.clicked.connect(self._step1_next)
        bh.addWidget(btn_next)

        v.addWidget(bottom)

        self._populate_devices()
        return outer

    def _populate_devices(self):
        """Populate partitions dynamically across operating systems using psutil."""
        self._drive_cards.clear()
        self._selected_drive_card = None
        self._selected_path_lbl.setText("No source selected")

        for grid in (self._drives_grid, self._ext_grid):
            while grid.count():
                item = grid.takeAt(0)
                w = item.widget()
                if w:
                    w.deleteLater()

        all_devs = _list_windows_partitions_native() if IS_WINDOWS else _list_system_partitions()

        COLS = 5
        count = 0
        for dev in all_devs:
            card = DriveCard(dev)
            card.clicked.connect(self._on_drive_card_clicked)
            self._drive_cards.append(card)
            row, col = divmod(count, COLS)
            self._drives_grid.addWidget(card, row, col)
            count += 1

        self._drives_section_label.setText(f"Detected Partitions({count})")
        self._ext_section_label.setText("External Drives(0)")

    def _on_drive_card_clicked(self, card: DriveCard):
        if self._selected_drive_card and self._selected_drive_card is not card:
            self._selected_drive_card.set_selected(False)
        for qc in self._qa_cards:
            qc.set_selected(False)

        card.set_selected(True)
        self._selected_drive_card = card

        raw_path = card.drive_info.get("path", "")
        self.source_path = _sanitise_source_path(raw_path)
        self._drive_total_sectors = card.drive_info.get("total_sectors", 0)
        self._drive_sector_size   = card.drive_info.get("sector_size", 512)
        self._drive_total_bytes   = card.drive_info.get("size_bytes", 0)

        gb_path = card.drive_info.get("gitbash_path", "")
        if self.source_path:
            if IS_GIT_BASH and gb_path:
                self._selected_path_lbl.setText(
                    f"Selected: {self.source_path}   🐚 Git Bash: {gb_path}"
                )
            else:
                self._selected_path_lbl.setText(f"Selected: {self.source_path}")
        else:
            self._selected_path_lbl.setText(
                f"Selected: {card.drive_info['label']}  ⚠ no device path"
            )

    def _on_qa_card_clicked(self, card: QuickAccessCard):
        if self._selected_drive_card:
            self._selected_drive_card.set_selected(False)
            self._selected_drive_card = None
        for qc in self._qa_cards:
            qc.set_selected(qc is card)

        if card.name == "Disk Image":
            self._browse_disk_image_qa()
        elif card.name == "Git Bash Path":
            self._enter_gitbash_path()
        elif card.name in ("Desktop", "Select Folder"):
            QMessageBox.information(
                self, "Select a Disk Image",
                f"'{card.name}' is a folder, not a raw disk image file.\n\n"
                "pytsk3 can only scan raw disk images (.img / .dd / .iso) or device paths.\n\n"
                "Use 'Disk Image' to browse for an image file, or select an active partition card above."
            )
            card.set_selected(False)
            self.source_path = ""
        elif card.name == "Recycle Bin":
            QMessageBox.information(
                self, "Not Supported",
                "Scanning individual system tracking directories directly is not supported.\n\n"
                "To recover files, select the appropriate partition card above or upload an image file."
            )
            card.set_selected(False)
            self.source_path = ""

    def _browse_disk_image_qa(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Disk Image", "",
            "Disk Images (*.img *.dd *.iso *.raw *.bin);;All Files (*)"
        )
        if path:
            self.source_path = _sanitise_source_path(path)
            self._drive_total_sectors = 0
            self._drive_sector_size   = 512
            try:
                self._drive_total_bytes = os.path.getsize(path)
            except Exception:
                self._drive_total_bytes = 0
            self._selected_path_lbl.setText(f"Selected: {self.source_path}")
        else:
            for qc in self._qa_cards:
                qc.set_selected(False)
            self.source_path = ""

    def _enter_gitbash_path(self):
        """
        Open a dialog where the user can paste a Git Bash / MSYS2 path and see
        the resolved native path before confirming.
        """
        from PyQt5.QtWidgets import QDialog, QDialogButtonBox

        dlg = QDialog(self)
        dlg.setWindowTitle("Enter Git Bash / MSYS2 Path")
        dlg.setMinimumWidth(520)
        dlg.setStyleSheet(self.styleSheet())

        dv = QVBoxLayout(dlg)
        dv.setContentsMargins(20, 16, 20, 16)
        dv.setSpacing(12)

        hint_lines = [
            "Paste a Git Bash (MSYS2) style path or a native Windows device path.",
            "",
            "  /c/images/disk.img      →  C:\\images\\disk.img",
            "  /c/                     →  \\\\.\\C:  (raw partition)",
            "  \\\\.\\PhysicalDrive0    →  used as-is",
            "  /dev/sda                →  Linux device (passed as-is on Linux/macOS)",
        ]
        hint = QLabel("\n".join(hint_lines))
        hint.setStyleSheet("color:#aaa; font-size:11px; font-family: monospace;")
        dv.addWidget(hint)

        input_row = QHBoxLayout()
        path_edit = QLineEdit()
        if IS_GIT_BASH:
            path_edit.setPlaceholderText("/c/path/to/disk.img  or  \\\\.\\PhysicalDrive0")
        else:
            path_edit.setPlaceholderText("/c/path/to/disk.img")
        path_edit.setStyleSheet(
            "background:#22252d; border:1px solid #3a3d45; border-radius:5px;"
            "padding:6px 10px; color:#ddd; font-family:monospace;"
        )
        input_row.addWidget(QLabel("Path:"))
        input_row.addWidget(path_edit, 1)
        dv.addLayout(input_row)

        resolved_lbl = QLabel("Resolved: —")
        resolved_lbl.setStyleSheet("color:#27ae60; font-size:11px; font-family:monospace;")
        dv.addWidget(resolved_lbl)

        def _on_text_changed(text):
            raw = text.strip()
            if not raw:
                resolved_lbl.setText("Resolved: —")
                resolved_lbl.setStyleSheet("color:#888; font-size:11px; font-family:monospace;")
                return
            resolved = _sanitise_source_path(raw)
            if resolved != raw:
                resolved_lbl.setText(f"Resolved: {resolved}")
                resolved_lbl.setStyleSheet("color:#27ae60; font-size:11px; font-family:monospace;")
            else:
                resolved_lbl.setText(f"Resolved: {resolved}  (no conversion needed)")
                resolved_lbl.setStyleSheet("color:#aaa; font-size:11px; font-family:monospace;")

        path_edit.textChanged.connect(_on_text_changed)

        env_note = QLabel(
            f"{'✅  Git Bash / MSYS2 environment detected — path conversion is active.' if IS_GIT_BASH else '⚠  Git Bash environment not detected — running standard ' + CURRENT_OS + ' mode.'}"
        )
        env_note.setStyleSheet(
            f"color:{'#27ae60' if IS_GIT_BASH else '#e67e22'}; font-size:11px;"
        )
        env_note.setWordWrap(True)
        dv.addWidget(env_note)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setStyleSheet("color:#ddd;")
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        dv.addWidget(buttons)

        if dlg.exec_() == QDialog.Accepted:
            raw = path_edit.text().strip()
            if raw:
                resolved = _sanitise_source_path(raw)
                self.source_path = resolved
                self._selected_path_lbl.setText(f"Selected (Git Bash): {resolved}")
            else:
                for qc in self._qa_cards:
                    qc.set_selected(False)
                self.source_path = ""
        else:
            for qc in self._qa_cards:
                qc.set_selected(False)
            self.source_path = ""

    def _step1_next(self):
        src = self.source_path.strip()

        if not src:
            QMessageBox.warning(self, "No Source", "Please select a drive card or a disk image file.")
            return

        if os.path.isdir(src):
            example_path = "\\\\.\\PhysicalDrive0  or  \\\\.\\D:" if IS_WINDOWS else "/dev/sda1"
            QMessageBox.critical(
                self, "Invalid Source",
                f"'{src}' is a directory.\n\n"
                "Both TSK and Carving modes require a raw disk image file or a valid device block path.\n\n"
                f"Example: {example_path}"
            )
            return

        self.source_path = src
        self._go_to_step(2)

    # ── Page 2: File Types ───────────────────────────────────────────────────

    def _page_filetypes(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(30, 24, 30, 24)
        v.setSpacing(14)

        lbl = QLabel("Step 2 — Select File Types & Scan Mode")
        lbl.setObjectName("step_label")
        v.addWidget(lbl)

        # ── Scan Mode ────────────────────────────────────────────────────────
        mode_group = QGroupBox("Scan Mode")
        mode_layout = QHBoxLayout(mode_group)
        mode_layout.setSpacing(20)

        self.radio_tsk = QRadioButton("🔬  TSK Mode  (pytsk3 filesystem — finds deleted file entries)")
        self.radio_tsk.setChecked(True)
        self.radio_carve = QRadioButton("🔍  Carving Mode  (signature scan — works on any raw image / drive)")
        self.radio_raw = QRadioButton("⚡  Raw Sector Mode  (fast sector-aligned scan — wide format support)")

        mode_layout.addWidget(self.radio_tsk)
        mode_layout.addWidget(self.radio_carve)
        mode_layout.addWidget(self.radio_raw)
        mode_layout.addStretch()

        def _on_mode_change():
            if self.radio_tsk.isChecked():
                self.scan_mode = "tsk"
            elif self.radio_carve.isChecked():
                self.scan_mode = "carving"
            else:
                self.scan_mode = "raw"
            # Carving and raw modes use fixed signature sets; grey out the type grid hint
            mode_note.setVisible(self.scan_mode != "tsk")
            if self.scan_mode == "raw":
                mode_note.setText(
                    "ℹ  Raw Sector Mode reads fixed 512-byte sectors and only matches "
                    "signatures sitting at the start of a sector. It's faster than "
                    "Carving Mode but can miss files whose header isn't sector-aligned. "
                    "Only formats it can detect are shown below — nothing is pre-checked, "
                    "pick what you want to look for."
                )
            else:
                mode_note.setText(
                    "ℹ  Carving mode uses built-in signatures for: "
                    + ", ".join(FILE_SIGNATURES.keys())
                    + ".  Custom extensions below are ignored in this mode."
                )
            self._apply_raw_filetype_filter(self.scan_mode == "raw")
        self.radio_tsk.toggled.connect(_on_mode_change)
        self.radio_carve.toggled.connect(_on_mode_change)
        self.radio_raw.toggled.connect(_on_mode_change)

        v.addWidget(mode_group)

        mode_note = QLabel(
            "ℹ  Carving mode uses built-in signatures for: "
            + ", ".join(FILE_SIGNATURES.keys())
            + ".  Custom extensions below are ignored in this mode."
        )
        mode_note.setStyleSheet("color:#e67e22; font-size:11px;")
        mode_note.setWordWrap(True)
        mode_note.setVisible(False)
        v.addWidget(mode_note)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        grid = QGridLayout(inner)
        grid.setSpacing(10)

        self._type_checks = {}
        self._group_checks = {}
        self._group_boxes = {}

        col = 0
        row = 0
        for group, exts in FILE_TYPE_GROUPS.items():
            grp_box = QGroupBox()
            gv = QVBoxLayout(grp_box)
            gv.setSpacing(4)

            header = QCheckBox(f"  {group}")
            header.setFont(QFont("Segoe UI", 11, QFont.Bold))
            header.setChecked(True)
            self._group_checks[group] = header
            self._group_boxes[group] = grp_box
            gv.addWidget(header)

            ext_checks = []
            for ext in exts:
                cb = QCheckBox(ext)
                cb.setChecked(True)
                gv.addWidget(cb)
                self._type_checks[ext] = cb
                ext_checks.append(cb)

            if group == "Others":
                note = QLabel("All other extensions")
                note.setStyleSheet("color:#888; font-size:11px; padding-left:22px;")
                gv.addWidget(note)

            def _make_toggle(checks):
                def toggle(state):
                    for c in checks:
                        c.setChecked(bool(state))
                return toggle
            header.stateChanged.connect(_make_toggle(ext_checks))

            grid.addWidget(grp_box, row, col)
            col += 1
            if col == 3:
                col = 0
                row += 1

        inner.setLayout(grid)
        scroll.setWidget(inner)
        v.addWidget(scroll, 1)

        cust_row = QHBoxLayout()
        self._custom_ext_label = QLabel("Custom extensions (comma-separated):")
        cust_row.addWidget(self._custom_ext_label)
        self.custom_ext_edit = QLineEdit()
        self.custom_ext_edit.setPlaceholderText(".psd, .ai, .sketch …")
        cust_row.addWidget(self.custom_ext_edit)
        v.addLayout(cust_row)

        nav = QHBoxLayout()
        btn_back = QPushButton("← Back")
        btn_back.clicked.connect(lambda: self._go_to_step(1))
        btn_scan = QPushButton("Start Scan  🔍")
        btn_scan.setObjectName("success")
        btn_scan.clicked.connect(self._start_scan)
        nav.addWidget(btn_back)
        nav.addStretch()
        nav.addWidget(btn_scan)
        v.addLayout(nav)
        return w

    def _apply_raw_filetype_filter(self, is_raw: bool):
        """
        Raw Sector Mode can only ever detect the formats in RAW_SUPPORTED_EXTS.
        When it's selected: hide every checkbox/group it can't detect, and
        leave the rest unchecked so the user explicitly picks what to look
        for (no defaults pre-selected). Switching back to TSK/Carving mode
        restores everything to visible + checked, the normal default.
        """
        for ext, cb in self._type_checks.items():
            supported = ext in RAW_SUPPORTED_EXTS
            if is_raw:
                cb.setVisible(supported)
                if supported:
                    cb.setChecked(False)
            else:
                cb.setVisible(True)
                cb.setChecked(True)

        for group, header in self._group_checks.items():
            group_exts = FILE_TYPE_GROUPS.get(group, [])
            any_supported = any(e in RAW_SUPPORTED_EXTS for e in group_exts)
            grp_box = self._group_boxes.get(group)
            if is_raw:
                if grp_box:
                    grp_box.setVisible(any_supported)
                header.setVisible(any_supported)
                if any_supported:
                    header.setChecked(False)
            else:
                if grp_box:
                    grp_box.setVisible(True)
                header.setVisible(True)
                header.setChecked(True)

        # Custom extensions can't be matched by Raw Sector Mode's fixed
        # signature table — disable that field while it's active.
        self.custom_ext_edit.setEnabled(not is_raw)
        self._custom_ext_label.setEnabled(not is_raw)
        if is_raw:
            self.custom_ext_edit.clear()

    def _get_selected_exts(self) -> set:
        exts = set()
        for ext, cb in self._type_checks.items():
            if cb.isChecked():
                exts.add(ext)
        custom = self.custom_ext_edit.text().strip()
        if custom:
            for part in custom.split(","):
                p = part.strip()
                if p:
                    exts.add(p if p.startswith(".") else "." + p)
        # Return empty set (= no filter = accept all) only when every known
        # type checkbox AND the Others catch-all are checked — i.e. the user
        # truly wants everything.  If the user has unchecked some types, the
        # non-empty exts set is used as a strict whitelist.
        others_checked = (
            self._group_checks.get("Others") and
            self._group_checks["Others"].isChecked()
        )
        all_known_checked = all(cb.isChecked() for cb in self._type_checks.values())
        if others_checked and all_known_checked:
            return set()   # accept all
        return exts

    # ── Page 3: Results ──────────────────────────────────────────────────────

    def _page_results(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(30, 24, 30, 24)
        v.setSpacing(12)

        lbl = QLabel("Step 3 — Scan Results & Preview")
        lbl.setObjectName("step_label")
        v.addWidget(lbl)

        # ── Drive info banner ────────────────────────────────────────────────────────────────────
        info_frame = QFrame()
        info_frame.setStyleSheet(
            "background:#1a2035; border:1px solid #2a3a5a; border-radius:8px;"
        )
        info_grid = QGridLayout(info_frame)
        info_grid.setContentsMargins(16, 10, 16, 10)
        info_grid.setHorizontalSpacing(32)
        info_grid.setVerticalSpacing(3)

        def _mk_title(text):
            l = QLabel(text)
            l.setStyleSheet("color:#5588bb; font-size:10px; font-weight:bold; letter-spacing:1px;")
            return l

        def _mk_val(text="—"):
            l = QLabel(text)
            l.setStyleSheet("color:#e0e0e0; font-size:12px; font-family:monospace;")
            return l

        # Hidden labels kept for compatibility with _on_scan_stats / _start_scan
        self._info_drive          = _mk_val()
        self._info_path           = _mk_val()
        self._info_total_sectors  = _mk_val()

        info_grid.addWidget(_mk_title("SCANNED SECTORS / TOTAL"), 0, 0)
        self._info_sectors = _mk_val()
        info_grid.addWidget(self._info_sectors,                   1, 0)
        info_grid.addWidget(_mk_title("SCANNED SIZE / TOTAL"),    0, 1)
        self._info_size    = _mk_val()
        info_grid.addWidget(self._info_size,                      1, 1)
        info_grid.addWidget(_mk_title("FILES FOUND"),             0, 2)
        self._info_files_found = _mk_val("0")
        self._info_files_found.setStyleSheet(
            "color:#2ecc71; font-size:14px; font-family:monospace; font-weight:bold;"
        )
        info_grid.addWidget(self._info_files_found,               1, 2)
        info_grid.setColumnStretch(3, 1)

        v.addWidget(info_frame)

        prog_row = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_label = QLabel("Waiting …")
        self.progress_label.setStyleSheet("color:#888;")
        prog_row.addWidget(self.progress_bar, 1)
        prog_row.addWidget(self.progress_label)
        v.addLayout(prog_row)

        ctrl_row = QHBoxLayout()
        self.btn_stop = QPushButton("⏹ Stop Scan")
        self.btn_stop.setObjectName("danger")
        self.btn_stop.clicked.connect(self._stop_scan)
        self.btn_stop.setEnabled(False)
        self.scan_summary = QLabel()
        self.scan_summary.setStyleSheet("color:#aaa;")
        ctrl_row.addWidget(self.btn_stop)
        ctrl_row.addSpacing(10)
        ctrl_row.addWidget(self.scan_summary)
        ctrl_row.addStretch()
        ctrl_row.addWidget(QLabel("Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("file name …")
        self.filter_edit.setFixedWidth(180)
        self.filter_edit.textChanged.connect(self._apply_filter)
        ctrl_row.addWidget(self.filter_edit)
        v.addLayout(ctrl_row)

        splitter = QSplitter(Qt.Horizontal)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["", "Name", "Extension", "Size", "Modified"])
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setDefaultSectionSize(90)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._on_select)
        self.table.itemChanged.connect(self._on_item_changed)
        self.table.setColumnWidth(0, 30)
        splitter.addWidget(self.table)

        prev_frame = QFrame()
        prev_frame.setObjectName("card")
        prev_frame.setMinimumWidth(220)
        pv = QVBoxLayout(prev_frame)
        pv.setContentsMargins(12, 12, 12, 12)
        pv.setSpacing(8)
        self.preview_img = QLabel("No preview")
        self.preview_img.setAlignment(Qt.AlignCenter)
        self.preview_img.setFixedHeight(180)
        self.preview_img.setStyleSheet("color:#555; border:1px solid #333; border-radius:6px;")
        pv.addWidget(self.preview_img)
        self.preview_info = QLabel()
        self.preview_info.setWordWrap(True)
        self.preview_info.setStyleSheet("color:#aaa; font-size:11px;")
        pv.addWidget(self.preview_info)
        pv.addStretch()
        splitter.addWidget(prev_frame)
        splitter.setSizes([700, 250])

        v.addWidget(splitter, 1)

        sel_row = QHBoxLayout()
        btn_all  = QPushButton("Select All")
        btn_none = QPushButton("Deselect All")
        btn_all.clicked.connect(lambda: self._select_all(True))
        btn_none.clicked.connect(lambda: self._select_all(False))
        self.selected_count = QLabel("0 selected")
        self.selected_count.setStyleSheet("color:#888;")
        sel_row.addWidget(btn_all)
        sel_row.addWidget(btn_none)
        sel_row.addSpacing(12)
        sel_row.addWidget(self.selected_count)
        sel_row.addStretch()
        v.addLayout(sel_row)

        nav = QHBoxLayout()
        btn_back = QPushButton("← Back")
        btn_back.clicked.connect(lambda: self._go_to_step(2))
        self.btn_recover = QPushButton("Recover Selected  →")
        self.btn_recover.setObjectName("success")
        self.btn_recover.clicked.connect(lambda: self._go_to_step(4))
        nav.addWidget(btn_back)
        nav.addStretch()
        nav.addWidget(self.btn_recover)
        v.addLayout(nav)
        return w

    # ── Page 4: Recover ──────────────────────────────────────────────────────

    def _page_recover(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(30, 24, 30, 24)
        v.setSpacing(16)

        lbl = QLabel("Step 4 — Recover Files")
        lbl.setObjectName("step_label")
        v.addWidget(lbl)

        warn_text = (
            "Choose where to save the recovered files. "
            "NEVER recover to the same drive partition you are scanning!"
        )
        sub = QLabel(warn_text)
        sub.setWordWrap(True)
        sub.setStyleSheet("color:#e67e22;")
        v.addWidget(sub)

        dest_row = QHBoxLayout()
        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText(
            "D:\\recovered\\" if IS_WINDOWS else "/home/user/recovered/"
        )
        btn_dest = QPushButton("Browse …")
        btn_dest.clicked.connect(self._browse_dest)
        dest_row.addWidget(QLabel("Destination:"))
        dest_row.addWidget(self.dest_edit, 1)
        dest_row.addWidget(btn_dest)
        v.addLayout(dest_row)

        self.recover_progress = QProgressBar()
        self.recover_progress.setRange(0, 100)
        v.addWidget(self.recover_progress)
        self.recover_label = QLabel()
        self.recover_label.setStyleSheet("color:#aaa;")
        v.addWidget(self.recover_label)

        self.recover_log = QListWidget()
        self.recover_log.setStyleSheet("font-size:11px; font-family:monospace;")
        v.addWidget(self.recover_log, 1)

        nav = QHBoxLayout()
        btn_back = QPushButton("← Back")
        btn_back.clicked.connect(lambda: self._go_to_step(3))
        self.btn_start_recover = QPushButton("▶  Start Recovery")
        self.btn_start_recover.setObjectName("success")
        self.btn_start_recover.clicked.connect(self._start_recovery)
        nav.addWidget(btn_back)
        nav.addStretch()
        nav.addWidget(self.btn_start_recover)
        v.addLayout(nav)
        return w

    # ── Navigation ───────────────────────────────────────────────────────────

    def _go_to_step(self, step: int):
        self.stack.setCurrentIndex(step - 1)
        style_active   = "color:#2e7dcc; font-weight:bold; background:transparent; border:none; font-size:13px;"
        style_inactive = "color:#555; font-weight:normal; background:transparent; border:none; font-size:13px;"
        for i, btn in enumerate(self._step_labels):
            btn.setStyleSheet(style_active if i + 1 == step else style_inactive)

    # ── Scan logic ───────────────────────────────────────────────────────────

    def _start_scan(self):
        self._go_to_step(3)
        self.found_files.clear()
        self.table.setRowCount(0)
        self.progress_bar.setValue(0)
        self.scan_summary.setText("")
        if hasattr(self, '_info_files_found'):
            self._info_files_found.setText("0")
        exts = self._get_selected_exts()

        # ── Populate drive info banner ────────────────────────────────────────
        src = self.source_path.strip()
        import re as _re2

        drive_label = "—"
        path_label  = src

        if IS_WINDOWS:
            m = _re2.search(r'([A-Za-z]):', src)
            if m:
                letter = m.group(1).upper()
                mount  = letter + ":\\"
                # Try to find the volume name from psutil (same as Windows Explorer)
                vol_name = ""
                try:
                    for part in psutil.disk_partitions(all=False):
                        mp = part.mountpoint.rstrip("\\/").upper()
                        if mp == letter + ":":
                            # psutil doesn't give volume label directly;
                            # use GetVolumeInformation on Windows
                            try:
                                import ctypes
                                buf = ctypes.create_unicode_buffer(256)
                                ctypes.windll.kernel32.GetVolumeInformationW(
                                    ctypes.c_wchar_p(mount), buf, 256,
                                    None, None, None, None, 0
                                )
                                vol_name = buf.value.strip()
                            except Exception:
                                pass
                            break
                except Exception:
                    pass
                if vol_name:
                    drive_label = f"{vol_name} ({letter}:)"
                else:
                    drive_label = f"{letter}:  (exists)" if os.path.exists(mount) else f"{letter}:"
                path_label = _native_to_gitbash_path(src) or src
        else:
            drive_label = os.path.basename(src) or src
            path_label  = src

        self._info_drive.setText(drive_label)
        self._info_path.setText(path_label)
        # Populate total sectors from drive card geometry if available
        if self._drive_total_sectors > 0:
            self._info_total_sectors.setText(f"{self._drive_total_sectors:,}")
        else:
            self._info_total_sectors.setText("—")
        if self._drive_total_bytes > 0:
            self._info_size.setText(f"— / {_human(self._drive_total_bytes)}")
        else:
            self._info_size.setText("—")
        self._info_sectors.setText("—")
        self._info_files_found.setText("0")

        # ── MSYS2/Git Bash path normalisation ────────────────────────────────
        # When Python runs inside Git Bash / MSYS2 it can silently translate
        # backslash device paths (e.g. \\.\.D:) to POSIX form (/d).
        # Force the stored source back to native Windows form before handing
        # it to any worker (pytsk3 and CreateFileW both need backslash paths).
        if IS_WINDOWS and self.source_path:
            src = self.source_path.replace("/", "\\")
            # If it looks like a bare drive letter after normalisation (e.g. "D:")
            # promote it to the UNC device path that pytsk3 expects.
            import re as _re
            if _re.match(r'^[A-Za-z]:$', src):
                src = f"\\\\.\\{src}"
            self.source_path = src

        if self.scan_mode == "carving":
            # Clean previous carving temp output
            if os.path.exists(self._carving_dir):
                shutil.rmtree(self._carving_dir, ignore_errors=True)
            os.makedirs(self._carving_dir, exist_ok=True)

            self.scan_worker = CarvingWorker(self.source_path, exts, self._carving_dir)
        elif self.scan_mode == "raw":
            # Clean previous raw-scan temp output
            if os.path.exists(self._raw_dir):
                shutil.rmtree(self._raw_dir, ignore_errors=True)
            os.makedirs(self._raw_dir, exist_ok=True)

            self.scan_worker = RawSectorScanWorker(self.source_path, exts, self._raw_dir)
        else:
            self.scan_worker = ScanWorker(self.source_path, exts)

        self.scan_worker.progress.connect(self._on_progress)
        self.scan_worker.file_found.connect(self._on_file_found)
        self.scan_worker.finished.connect(self._on_scan_done)
        self.scan_worker.error.connect(self._on_scan_error)
        # stats signal is only present on RawSectorScanWorker
        if hasattr(self.scan_worker, "stats"):
            self.scan_worker.stats.connect(self._on_scan_stats)
        self.btn_stop.setEnabled(True)
        self.scan_worker.start()

    def _stop_scan(self):
        if self.scan_worker:
            self.scan_worker.stop()
        self.btn_stop.setEnabled(False)

    def _on_progress(self, pct, msg):
        self.progress_bar.setValue(pct)
        self.progress_label.setText(msg)
        self.status_bar.showMessage(msg)

    def _on_scan_stats(self, current_sector: int, total_sectors: int):
        """Live-update the drive info banner — called every sector from RawSectorScanWorker."""
        sector_size   = self._drive_sector_size or 512
        scanned_bytes = current_sector * sector_size
        # Use known drive geometry if worker didn't supply totals yet
        eff_total = total_sectors if total_sectors > 0 else self._drive_total_sectors
        total_bytes = eff_total * sector_size if eff_total > 0 else self._drive_total_bytes

        if eff_total > 0:
            self._info_total_sectors.setText(f"{eff_total:,}")
            self._info_sectors.setText(f"{current_sector:,} / {eff_total:,}")
            self._info_size.setText(f"{_human(scanned_bytes)} / {_human(total_bytes)}")
            # Fix progress bar with real percentage
            pct = min(99, int(current_sector * 100 / eff_total))
            self.progress_bar.setValue(pct)
        else:
            self._info_sectors.setText(f"{current_sector:,}")
            self._info_size.setText(_human(scanned_bytes))

    def _on_file_found(self, info: dict):
        self.found_files.append(info)
        row = self.table.rowCount()
        self.table.blockSignals(True)
        self.table.insertRow(row)

        chk = QTableWidgetItem()
        chk.setCheckState(Qt.Unchecked)
        # ItemIsUserCheckable  — lets the user click to check/uncheck
        # ItemIsEnabled        — not greyed out
        # NOT ItemIsSelectable — checkbox column doesn't participate in row selection highlight
        chk.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        self.table.setItem(row, 0, chk)

        self.table.setItem(row, 1, QTableWidgetItem(info["name"]))
        self.table.setItem(row, 2, QTableWidgetItem(info["ext"] or "(none)"))
        sz_item = QTableWidgetItem(_human(info["size"]))
        sz_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.table.setItem(row, 3, sz_item)
        self.table.setItem(row, 4, QTableWidgetItem(info["mtime"]))
        self.table.blockSignals(False)
        total_found = len(self.found_files)
        self.scan_summary.setText(f"Found {total_found} deleted file(s)")
        self._info_files_found.setText(str(total_found))

    def _on_scan_done(self, count: int):
        self.progress_bar.setValue(100)
        self.progress_label.setText(f"Scan complete — {count} deleted file(s) found")
        self.btn_stop.setEnabled(False)
        self._info_files_found.setText(str(count))
        self.status_bar.showMessage(f"Scan complete. {count} deleted files found.")

    def _on_scan_error(self, msg: str):
        self.btn_stop.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Error during scan")
        QMessageBox.critical(self, "Scan Error", msg)

    def _on_item_changed(self, item):
        """Called whenever any cell changes — only care about column 0 (checkbox)."""
        if item.column() == 0:
            self._refresh_selected_count()

    def _apply_filter(self, text: str):
        text = text.lower()
        for row in range(self.table.rowCount()):
            name = self.table.item(row, 1)
            hidden = bool(text) and name and text not in name.text().lower()
            self.table.setRowHidden(row, hidden)

    def _select_all(self, checked: bool):
        state = Qt.Checked if checked else Qt.Unchecked
        for row in range(self.table.rowCount()):
            chk = self.table.item(row, 0)
            if chk:
                chk.setCheckState(state)
        self._refresh_selected_count()

    def _refresh_selected_count(self):
        n = sum(
            1 for row in range(self.table.rowCount())
            if self.table.item(row, 0) and
               self.table.item(row, 0).checkState() == Qt.Checked
        )
        self.selected_count.setText(f"{n} selected")

    def _on_select(self):
        self._refresh_selected_count()
        rows = self.table.selectedItems()
        if not rows:
            return
        row = self.table.currentRow()
        if row < 0 or row >= len(self.found_files):
            return
        info = self.found_files[row]
        ext  = info["ext"].lower()

        self.preview_img.setText("No preview")
        self.preview_img.setPixmap(QPixmap())
        if PIL_AVAILABLE and ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
            try:
                fs   = info["fs"]
                ino  = info["inode"]
                size = info["size"]
                if fs and ino and size > 0 and size < 50 * 1024 * 1024:
                    fe   = fs.open_meta(inode=ino)
                    data = fe.read_random(0, min(size, 4 * 1024 * 1024))
                    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tf:
                        tf.write(data)
                        tpath = tf.name
                    img = Image.open(tpath)
                    img.thumbnail((200, 160))
                    img_rgb = img.convert("RGB")
                    qimg = QImage(
                        img_rgb.tobytes(), img_rgb.width, img_rgb.height,
                        img_rgb.width * 3, QImage.Format_RGB888
                    )
                    self.preview_img.setPixmap(QPixmap.fromImage(qimg))
                    os.unlink(tpath)
            except Exception:
                pass

        info_txt = (
            f"<b>{info['name']}</b><br>"
            f"Path: {info['path']}<br>"
            f"Size: {_human(info['size'])}<br>"
            f"Modified: {info['mtime']}<br>"
            f"Inode: {info.get('inode', 'N/A')}"
        )
        self.preview_info.setText(info_txt)

    # ── Recovery ─────────────────────────────────────────────────────────────

    def _browse_dest(self):
        path = QFileDialog.getExistingDirectory(self, "Select Destination Folder")
        if path:
            self.dest_edit.setText(path)

    def _start_recovery(self):
        dest = self.dest_edit.text().strip()
        if not dest:
            QMessageBox.warning(self, "No Destination", "Please select a destination folder.")
            return
        os.makedirs(dest, exist_ok=True)

        selected = []
        for row in range(self.table.rowCount()):
            chk = self.table.item(row, 0)
            if chk and chk.checkState() == Qt.Checked and not self.table.isRowHidden(row):
                if row < len(self.found_files):
                    selected.append(self.found_files[row])

        if not selected:
            QMessageBox.warning(self, "Nothing Selected", "Please select at least one file to recover.")
            return

        self.recover_log.clear()
        self.recover_progress.setValue(0)
        self.btn_start_recover.setEnabled(False)

        # Carving / Raw modes: files are already written to temp dir — just copy them
        if self.scan_mode in ("carving", "raw") and selected and selected[0].get("carved_path"):
            self._recover_carved_files(selected, dest)
            return

        self.recover_worker = RecoverWorker(selected, dest, self.source_path)
        self.recover_worker.progress.connect(self._on_recover_progress)
        self.recover_worker.finished.connect(self._on_recover_done)
        self.recover_worker.error.connect(self._on_recover_error)
        self.recover_worker.start()

    def _recover_carved_files(self, selected: list, dest: str):
        """Copy already-carved temp files to the user's chosen destination."""
        success = failed = 0
        self.recover_log.clear()
        self.recover_progress.setValue(0)
        self.btn_start_recover.setEnabled(False)
        total = len(selected)
        for i, finfo in enumerate(selected):
            src = finfo.get("carved_path", "")
            pct = int((i / total) * 100)
            self.recover_progress.setValue(pct)
            msg = f"Copying {finfo['name']} …"
            self.recover_label.setText(msg)
            item = QListWidgetItem(f"[{pct:3d}%] {msg}")
            item.setForeground(QColor("#aaa"))
            self.recover_log.addItem(item)
            self.recover_log.scrollToBottom()
            QApplication.processEvents()
            try:
                out_path = os.path.join(dest, finfo["name"])
                base, ext2 = os.path.splitext(out_path)
                counter = 1
                while os.path.exists(out_path):
                    out_path = f"{base}_{counter}{ext2}"
                    counter += 1
                shutil.copy2(src, out_path)
                success += 1
            except Exception:
                failed += 1
        self._on_recover_done(success, failed)

    def _on_recover_progress(self, pct, msg):
        self.recover_progress.setValue(pct)
        self.recover_label.setText(msg)
        item = QListWidgetItem(f"[{pct:3d}%] {msg}")
        item.setForeground(QColor("#aaa"))
        self.recover_log.addItem(item)
        self.recover_log.scrollToBottom()

    def _on_recover_done(self, success, failed):
        self.recover_progress.setValue(100)
        self.btn_start_recover.setEnabled(True)
        msg = f"✅ Recovery complete!  Recovered: {success}   Failed: {failed}"
        self.recover_label.setText(msg)
        item = QListWidgetItem(msg)
        item.setForeground(QColor("#27ae60"))
        self.recover_log.addItem(item)
        self.status_bar.showMessage(msg)
        QMessageBox.information(
            self, "Done",
            f"Recovery finished.\n\nSuccessful: {success}\nFailed: {failed}\n\n"
            f"Files saved to:\n{self.dest_edit.text()}"
        )

    def _on_recover_error(self, msg):
        self.btn_start_recover.setEnabled(True)
        QMessageBox.critical(self, "Recovery Error", msg)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = FileRecoveryApp()
    window.show()
    sys.exit(app.exec_())