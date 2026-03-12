#!/usr/bin/env python3
"""
start_with_tor.py
-----------------
Orchestrates the full secureChat startup on Windows (and Linux/macOS):

  1. Finds or downloads the Tor Expert Bundle (Windows).
  2. Starts Tor as a subprocess with a hidden-service configuration.
  3. Waits for Tor to bootstrap and write the .onion hostname file.
  4. Prints the public .onion address.
  5. Runs the aiohttp chat server in the same process.

The hidden-service directory is stored in ``tor_hs/`` next to this script,
so the .onion address remains the same across restarts.

Usage:
    python start_with_tor.py

Environment variables (forwarded to server.py):
    PORT           TCP port for the local server (default: 5000)
    HOST           Interface to bind (default: 127.0.0.1 — keep as-is for Tor)
    DB_PATH        Path to SQLite database
    HISTORY_LIMIT  Messages to store/replay per room
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent

# Local directory where the Tor Expert Bundle is extracted (Windows auto-download)
_TOR_DIR = _HERE / "tor"
# Hidden-service directory created by Tor — persists the .onion key/address
_HS_DIR = _HERE / "tor_hs"
# Tor's data directory
_TOR_DATA_DIR = _HERE / "tor_data"

SERVER_PORT = int(os.environ.get("PORT", "5000"))

# ---------------------------------------------------------------------------
# Tor Expert Bundle download URL (Windows x86_64)
# ---------------------------------------------------------------------------
# Keep in sync with https://www.torproject.org/download/tor/
_TOR_VERSION = "14.0.9"
_TOR_BUNDLE_URL = (
    f"https://dist.torproject.org/torbrowser/{_TOR_VERSION}/"
    f"tor-expert-bundle-windows-x86_64-{_TOR_VERSION}.tar.gz"
)


# ---------------------------------------------------------------------------
# Locate tor executable
# ---------------------------------------------------------------------------

def _find_tor() -> Optional[Path]:
    """Return the path to a usable tor executable, or None if not found."""
    # 1. Previously auto-downloaded bundle (tor/ sub-directory)
    for rel in ["tor/Tor/tor.exe", "tor/tor.exe", "tor/tor"]:
        p = _HERE / rel
        if p.is_file():
            return p

    # 2. System PATH
    found = shutil.which("tor")
    if found:
        return Path(found)

    # 3. Tor Browser bundled tor.exe — check common Windows install paths
    if platform.system() == "Windows":
        username = os.environ.get("USERNAME", "")
        home = Path.home()
        candidates = [
            home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path(f"C:/Users/{username}/Desktop/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            # Tor Expert Bundle extracted to default location
            Path(f"C:/Users/{username}/AppData/Local/tor/Tor/tor.exe"),
        ]
        for c in candidates:
            try:
                if c.is_file():
                    return c
            except (OSError, ValueError):
                pass

    return None


def _download_tor() -> Optional[Path]:
    """Download the Tor Expert Bundle (Windows) and extract tor.exe.

    Returns the path to tor.exe, or None on failure.
    """
    if platform.system() != "Windows":
        print(
            "\n  Tor not found.  Please install Tor via your package manager:\n"
            "    Linux:  sudo apt install tor  (or equivalent)\n"
            "    macOS:  brew install tor\n"
            "  Then restart this script."
        )
        return None

    _TOR_DIR.mkdir(parents=True, exist_ok=True)
    archive = _TOR_DIR / "tor-expert-bundle.tar.gz"

    print(f"\n  Tor not found — downloading Tor Expert Bundle from torproject.org …")
    print(f"  URL: {_TOR_BUNDLE_URL}")
    try:
        urllib.request.urlretrieve(_TOR_BUNDLE_URL, archive)
    except urllib.error.URLError as exc:
        print(f"\n  Download failed: {exc}")
        print(
            "  Please download the Tor Expert Bundle manually from:\n"
            "    https://www.torproject.org/download/tor/\n"
            "  Extract it so that tor.exe is at  tor\\Tor\\tor.exe  "
            "next to start_server.bat."
        )
        return None

    # Verify the archive with the SHA-256 checksum published by the Tor Project
    sha256_url = _TOR_BUNDLE_URL + ".sha256sum"
    sha256_file = _TOR_DIR / "tor-expert-bundle.tar.gz.sha256sum"
    try:
        urllib.request.urlretrieve(sha256_url, sha256_file)
        expected_hex = sha256_file.read_text(encoding="utf-8").split()[0].lower()

        actual_hex = hashlib.sha256(archive.read_bytes()).hexdigest().lower()
        if actual_hex != expected_hex:
            print(
                f"\n  SHA-256 verification FAILED.\n"
                f"  Expected: {expected_hex}\n"
                f"  Actual:   {actual_hex}\n"
                "  The downloaded archive may be corrupted or tampered with.\n"
                "  Aborting for your safety."
            )
            try:
                archive.unlink()
            except OSError:
                pass
            return None
        print("  SHA-256 verified.")
    except urllib.error.URLError as exc:
        print(f"  Warning: could not fetch checksum file ({exc}); skipping verification.")
    finally:
        try:
            sha256_file.unlink()
        except OSError:
            pass

    print("  Extracting …")
    try:
        with tarfile.open(archive) as tf:
            # Filter members to prevent path-traversal attacks (absolute paths
            # or members with ".." components are silently skipped).
            safe_members = [
                m for m in tf.getmembers()
                if not os.path.isabs(m.name) and ".." not in m.name.split("/")
            ]
            tf.extractall(_TOR_DIR, members=safe_members)
    except Exception as exc:
        print(f"  Extraction failed: {exc}")
        return None
    finally:
        try:
            archive.unlink()
        except OSError:
            pass

    # The bundle typically extracts to Tor/tor.exe
    for rel in ["Tor/tor.exe", "tor.exe"]:
        p = _TOR_DIR / rel
        if p.is_file():
            print(f"  Tor ready: {p}")
            return p

    print("  Could not locate tor.exe inside the extracted archive.")
    return None


# ---------------------------------------------------------------------------
# Launch Tor with a hidden service
# ---------------------------------------------------------------------------

def _tor_log(line: str) -> None:
    """Print Tor bootstrap / error lines to help the user follow progress."""
    if "Bootstrapped" in line or "[err]" in line.lower() or "[warn]" in line.lower():
        print(f"  [Tor] {line.rstrip()}")


def _start_tor_hidden_service(tor_exe: Path) -> Optional[tuple]:
    """Launch tor with a hidden-service configuration.

    Returns ``(onion_address, tor_process)`` on success, or ``None`` on failure.
    The caller is responsible for terminating *tor_process* when done.
    """
    try:
        import stem.process  # noqa: PLC0415
    except ImportError:
        print("  stem is not installed.  Run:  pip install stem")
        return None

    _HS_DIR.mkdir(parents=True, exist_ok=True)
    _TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("\n  Starting Tor …  (this may take up to 90 seconds on first run)")

    try:
        tor_process = stem.process.launch_tor_with_config(
            tor_cmd=str(tor_exe),
            config={
                "SocksPort": "0",
                "ControlPort": "9151",
                "DataDirectory": str(_TOR_DATA_DIR),
                "HiddenServiceDir": str(_HS_DIR),
                "HiddenServicePort": f"80 127.0.0.1:{SERVER_PORT}",
            },
            timeout=90,
            init_msg_handler=_tor_log,
        )
    except OSError as exc:
        print(f"\n  Tor failed to start: {exc}")
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"\n  Tor failed to start: {exc}")
        return None

    # Wait for Tor to write the hostname file (created after bootstrap)
    hostname_file = _HS_DIR / "hostname"
    for _ in range(60):
        if hostname_file.is_file():
            onion = hostname_file.read_text(encoding="utf-8").strip()
            return onion, tor_process
        time.sleep(1)

    print("  Timed out waiting for the .onion hostname file.")
    tor_process.terminate()
    return None


# ---------------------------------------------------------------------------
# Run the aiohttp server
# ---------------------------------------------------------------------------

def _run_server() -> None:
    import server as srv  # noqa: PLC0415
    from aiohttp import web  # noqa: PLC0415

    host = os.environ.get("HOST", "127.0.0.1")
    web.run_app(srv.build_app(), host=host, port=SERVER_PORT, access_log=None)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 60)
    print("  secureChat — starting with Tor hidden service")
    print("=" * 60)

    # ── 1. Find / download tor.exe ───────────────────────────────────
    tor_exe = _find_tor()
    if not tor_exe:
        tor_exe = _download_tor()

    if not tor_exe:
        print(
            "\n  Could not find or download tor.exe.\n"
            "  Starting server locally only (no .onion address).\n"
            f"  Local access: http://127.0.0.1:{SERVER_PORT}"
        )
        _run_server()
        return

    # ── 2. Start Tor + hidden service ────────────────────────────────
    result = _start_tor_hidden_service(tor_exe)

    if result is None:
        print(
            "\n  Tor hidden service could not be started.\n"
            "  Starting server locally only (no .onion address).\n"
            f"  Local access: http://127.0.0.1:{SERVER_PORT}"
        )
        _run_server()
        return

    onion_address, tor_process = result

    # ── 3. Display the .onion URL ────────────────────────────────────
    print()
    print("=" * 60)
    print("  🧅  Your public .onion address:")
    print()
    print(f"      http://{onion_address}")
    print()
    print("  Share this URL (via a separate secure channel) together")
    print("  with the Room ID and Passphrase.  Both parties must")
    print("  open it in Tor Browser.")
    print("=" * 60)
    print()
    print(f"  Local access:  http://127.0.0.1:{SERVER_PORT}")
    print()
    print("  Press Ctrl+C to stop.")
    print()

    # ── 4. Run the server (blocks until Ctrl+C) ──────────────────────
    try:
        _run_server()
    finally:
        try:
            tor_process.terminate()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    main()
