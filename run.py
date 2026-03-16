#!/usr/bin/env python3
"""
run.py — secureChat zero-config launcher
=========================================
Run this single file.  It handles everything automatically:

  1. Installs missing Python dependencies.
  2. Loads optional .env file (if present next to run.py).
  3. Starts Tor and creates a public .onion hidden service
     (downloads the Tor Expert Bundle on Windows if needed).
  4. Generates a random RELAY_SECRET for the IP-private SMTP relay endpoint.
  5. Starts the secureChat server.
  6. Prints a startup summary with every URL you need.

Usage
-----
    python run.py                 # default port 5000
    python run.py --port 8080     # custom port

Environment overrides (all optional — every default works out-of-the-box)
--------------------------------------------------------------------------
    PORT           TCP port for the server        (default: 5000)
    HOST           Bind interface                 (default: 127.0.0.1 with Tor, 0.0.0.0 without)
    DB_PATH        Path to SQLite database        (default: securechat.db next to run.py)
    RELAY_SECRET   SMTP relay webhook secret      (auto-generated when not set)
    MAIL_DOMAIN    Your real mail domain for SMTP (optional; needed for port-25 SMTP)
    SMTP_PORT      SMTP listen port               (default: 25)
    MESH_JOIN      URL of a remote peer to auto-join at startup (optional)
    MESH_TOKEN     MESH_TOKEN of the remote peer  (required when MESH_JOIN is set)
    LOCAL_MESH_PORT  Port for the local mesh hub (default: disabled).  When set, the hub
                   (local_mesh.py) is started automatically if not already running, and
                   this instance registers with it.  Run multiple instances on the same
                   machine with the same LOCAL_MESH_PORT to form a local cluster.
    NO_TOR         Set to '1' to skip Tor even if installed (optional)
    TOR_PATH       Override path to the tor binary (optional)

All of the above can also be set in a .env file placed next to run.py.
The .env file is loaded once at startup; command-line flags take precedence.

No other configuration is needed.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent

# Canonical upstream repository — used by AUTO_UPDATE to (re)point the git
# remote when the repo was downloaded as a zip or cloned from a local path.
_GITHUB_URL = "https://github.com/Kitywiel/secureChat-1.0"
_REQUIREMENTS = _HERE / "requirements.txt"
_DOTENV       = _HERE / ".env"

# Tor paths (mirrors start_with_tor.py so they share the same downloaded bundle)
_TOR_DIR      = _HERE / "tor"
_HS_DIR       = _HERE / "tor_hs"
_TOR_DATA_DIR = _HERE / "tor_data"

# Tor Expert Bundle download (Windows auto-download)
_TOR_VERSION    = "14.0.9"
_TOR_BUNDLE_URL = (
    f"https://dist.torproject.org/torbrowser/{_TOR_VERSION}/"
    f"tor-expert-bundle-windows-x86_64-{_TOR_VERSION}.tar.gz"
)

# ---------------------------------------------------------------------------
# .env loader — loads KEY=VALUE pairs from .env file (if present)
# Existing environment variables are NOT overwritten.
# ---------------------------------------------------------------------------

def _load_dotenv() -> None:
    """Load a .env file next to run.py into os.environ (non-overwriting)."""
    if not _DOTENV.is_file():
        return
    try:
        for raw in _DOTENV.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = val
    except OSError:
        pass  # .env unreadable — silently skip

_load_dotenv()


# ---------------------------------------------------------------------------
# Config-file key removal helper
# ---------------------------------------------------------------------------

def _remove_keys_from_config(keys: set[str]) -> None:
    """Remove ``KEY=...`` lines from ``.env`` and ``SET KEY=...`` from ``.bat``.

    Used by ``--new-mesh-url`` and ``--new-onion-url`` to clear persisted
    secrets so fresh values are generated on the next (current) startup.
    """
    keys_upper = {k.upper() for k in keys}

    # ── .env ──────────────────────────────────────────────────────────────
    if _DOTENV.is_file():
        try:
            lines = _DOTENV.read_text(encoding="utf-8").splitlines(keepends=True)
            new_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped and not stripped.startswith("#") and "=" in stripped:
                    k, _, _ = stripped.partition("=")
                    k_upper = k.strip().upper()
                    if k_upper in keys_upper:
                        continue  # drop this key
                new_lines.append(line)
            _DOTENV.write_text("".join(new_lines), encoding="utf-8")
        except OSError:
            pass

    # ── start_server.bat ──────────────────────────────────────────────────
    bat = _HERE / "start_server.bat"
    if bat.is_file():
        try:
            lines = bat.read_text(encoding="utf-8").splitlines(keepends=True)
            new_lines = []
            for line in lines:
                stripped = line.strip()
                if stripped.upper().startswith("SET ") and "=" in stripped:
                    key = stripped[4:].partition("=")[0].strip().upper()
                    if key in keys_upper:
                        continue  # drop this key
                new_lines.append(line)
            bat.write_text("".join(new_lines), encoding="utf-8")
        except OSError:
            pass


# ---------------------------------------------------------------------------

def _auto_update() -> None:
    """Pull the latest code from the remote git repository.

    Enabled by setting ``AUTO_UPDATE=1`` (or ``true`` / ``yes``) in ``.env``
    or in the shell environment.  Disabled by default so that users who run
    from a custom checkout or without git are never surprised.

    **Zero-setup behaviour** — no manual git clone needed:

    * If the directory is not yet a git repository, one is initialised
      automatically and the latest code is fetched from ``_GITHUB_URL`` so
      that updates work from the very first run.
    * If the ``origin`` remote points to a local path (e.g. the repo was
      cloned from a local copy instead of GitHub), the URL is corrected
      automatically before pulling.
    * If ``git pull`` fails for any reason (merge conflicts, network error, …)
      a warning is printed and the server starts normally.
    * If new files were pulled, the user is notified and asked to restart
      manually — the server continues with the pre-update code for safety.
    """
    enabled = os.environ.get("AUTO_UPDATE", "").strip().lower() in ("1", "true", "yes")
    if not enabled:
        return

    print("  AUTO_UPDATE enabled — checking for updates via git …")

    # Confirm git binary is available.
    git_bin = shutil.which("git")
    if not git_bin:
        print("  WARNING: AUTO_UPDATE=1 but 'git' was not found on PATH — skipping.")
        return

    # ── 1. Ensure we are inside a git repository ────────────────────────────
    # Using `git rev-parse` handles normal clones (.git dir), worktrees, and
    # subdirectory layouts — a plain `.git` directory check misses these.
    try:
        rev = subprocess.run(
            [git_bin, "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            cwd=str(_HERE),
            timeout=5,
        )
        is_repo = rev.returncode == 0
    except Exception:  # noqa: BLE001
        is_repo = False

    if not is_repo:
        # Not a git repo — initialise one pointing to GitHub so that this and
        # all future runs can auto-update without any manual setup.
        print(f"  Not a git repository — installing from {_GITHUB_URL} …")
        try:
            subprocess.run(
                [git_bin, "init"],
                capture_output=True, cwd=str(_HERE), timeout=10,
            )
            subprocess.run(
                [git_bin, "remote", "add", "origin", _GITHUB_URL],
                capture_output=True, cwd=str(_HERE), timeout=10,
            )
            fetch = subprocess.run(
                [git_bin, "fetch", "origin", "--depth=1"],
                capture_output=True, text=True, cwd=str(_HERE), timeout=60,
            )
            if fetch.returncode == 0:
                # Check out the default branch (try main then master).
                checked_out = False
                for branch in ("main", "master"):
                    co = subprocess.run(
                        [git_bin, "checkout", "-f", branch],
                        capture_output=True, cwd=str(_HERE), timeout=10,
                    )
                    if co.returncode == 0:
                        checked_out = True
                        break
                if not checked_out:
                    subprocess.run(
                        [git_bin, "reset", "--hard", "FETCH_HEAD"],
                        capture_output=True, cwd=str(_HERE), timeout=10,
                    )
                print(
                    "  ✅  Repository installed from GitHub.\n"
                    "       Restart run.py to start with the freshly downloaded code."
                )
            else:
                print(
                    "  ⚠️  Git initialised but fetch failed — check your internet "
                    "connection.\n"
                    "       AUTO_UPDATE will retry on next restart."
                )
        except Exception as exc:  # noqa: BLE001
            print(f"  WARNING: Could not set up git repository ({exc}).")
        return  # Don't also run pull on the first-install run.

    # ── 2. Ensure origin points to a network URL, not a local path ──────────
    _network_schemes = ("http://", "https://", "git@", "git://", "ssh://")
    try:
        remote_res = subprocess.run(
            [git_bin, "remote", "get-url", "origin"],
            capture_output=True, text=True, cwd=str(_HERE), timeout=5,
        )
        remote_url = remote_res.stdout.strip() if remote_res.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        remote_url = ""

    if not remote_url:
        # No origin remote — add the canonical GitHub URL.
        print(f"  No 'origin' remote found — adding {_GITHUB_URL} …")
        try:
            subprocess.run(
                [git_bin, "remote", "add", "origin", _GITHUB_URL],
                capture_output=True, cwd=str(_HERE), timeout=10,
            )
        except Exception:  # noqa: BLE001
            pass
    elif not any(remote_url.startswith(s) for s in _network_schemes):
        # Origin is a local path — fix it to the canonical GitHub URL.
        print(
            f"  Remote 'origin' points to a local path ({remote_url!r}) — "
            f"updating to {_GITHUB_URL} …"
        )
        try:
            subprocess.run(
                [git_bin, "remote", "set-url", "origin", _GITHUB_URL],
                capture_output=True, cwd=str(_HERE), timeout=10,
            )
            print(f"  ✅  Remote updated to {_GITHUB_URL}")
        except Exception as exc:  # noqa: BLE001
            print(f"  WARNING: Could not update remote URL ({exc}) — skipping auto-update.")
            return

    # ── 3. Pull latest code from main ───────────────────────────────────────
    try:
        result = subprocess.run(
            [git_bin, "pull", "--ff-only", "origin", "main"],
            capture_output=True,
            text=True,
            cwd=str(_HERE),
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        print("  WARNING: git pull timed out — starting with existing code.")
        return
    except Exception as exc:  # noqa: BLE001
        print(f"  WARNING: git pull failed ({exc}) — starting with existing code.")
        return

    if result.returncode != 0:
        print(
            "  WARNING: git pull reported an error — starting with existing code.\n"
            f"           {result.stderr.strip()[:200]}"
        )
        return

    output = result.stdout.strip()
    if output and output != "Already up to date.":
        print(f"  ✅  Repository updated:\n    {output}")
        print(
            "\n  ⚠️  New files were pulled.  Restart run.py to apply the updates.\n"
            "       The server will now start with the pre-update code for safety.\n"
        )
    else:
        print("  Already up to date.")


# ---------------------------------------------------------------------------
# Step 1 — Auto-install dependencies
# ---------------------------------------------------------------------------

def _ensure_dependencies() -> None:
    """Install any missing packages listed in requirements.txt."""
    if not _REQUIREMENTS.is_file():
        return

    print("  Checking Python dependencies …")
    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "install",
            "--quiet", "--disable-pip-version-check",
            "-r", str(_REQUIREMENTS),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(
            "\n  WARNING: pip install reported errors.  The server may still work "
            "if all packages are already installed.\n"
        )
        print(result.stderr[:1000])
    else:
        print("  Dependencies OK.")


# ---------------------------------------------------------------------------
# Step 2 — Tor helpers (adapted from start_with_tor.py)
# ---------------------------------------------------------------------------

def _find_tor() -> Path | None:
    """Return the path to a usable tor executable, or None.

    Search order:
      1. TOR_PATH env var (absolute path override).
      2. Local bundle — tor/ sub-directory next to run.py.
      3. System PATH via shutil.which.
      4. Common installation locations on Linux, macOS, and Windows.
    """
    # 1. Explicit override
    tor_env = os.environ.get("TOR_PATH", "").strip()
    if tor_env:
        p = Path(tor_env)
        if p.is_file():
            return p

    # 2. Local bundled tor
    for rel in ["tor/Tor/tor.exe", "tor/tor.exe", "tor/tor"]:
        p = _HERE / rel
        if p.is_file():
            return p

    # 3. PATH
    found = shutil.which("tor")
    if found:
        return Path(found)

    # 4. Common system-wide paths (Linux / macOS / Windows)
    candidates: list[Path] = []
    system = platform.system()

    if system in ("Linux", "Darwin"):
        candidates.extend([
            Path("/usr/bin/tor"),
            Path("/usr/local/bin/tor"),
            Path("/usr/sbin/tor"),
            Path("/opt/homebrew/bin/tor"),          # Homebrew Apple Silicon
            Path("/opt/local/bin/tor"),              # MacPorts
            Path("/snap/bin/tor"),                   # Snap on Ubuntu
            Path("/usr/lib/tor/tor"),
            Path("/usr/libexec/tor/tor"),
        ])

    if system == "Windows":
        home = Path.home()
        username = os.environ.get("USERNAME", "")
        candidates.extend([
            home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
            Path(f"C:/Users/{username}/Desktop/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            Path("C:/Program Files/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
            Path("C:/Program Files (x86)/Tor Browser/Browser/TorBrowser/Tor/tor.exe"),
        ])

    for c in candidates:
        try:
            if c.is_file():
                return c
        except (OSError, ValueError):
            pass

    return None


def _download_tor_windows() -> Path | None:
    """Download the Tor Expert Bundle on Windows.  Returns path to tor.exe."""
    if platform.system() != "Windows":
        return None
    _TOR_DIR.mkdir(parents=True, exist_ok=True)
    archive = _TOR_DIR / "tor-expert-bundle.tar.gz"
    print(f"  Downloading Tor Expert Bundle from torproject.org …")
    try:
        urllib.request.urlretrieve(_TOR_BUNDLE_URL, archive)
    except urllib.error.URLError as exc:
        print(f"  Download failed: {exc}")
        print("  Tip: ensure you have internet access and torproject.org is not blocked.")
        print(f"  You can also manually download the Tor Expert Bundle and place tor.exe at:")
        print(f"    {_TOR_DIR / 'Tor' / 'tor.exe'}  or  {_TOR_DIR / 'tor.exe'}")
        return None
    except Exception as exc:  # noqa: BLE001
        print(f"  Download failed (unexpected error): {exc}")
        return None

    # SHA-256 verification
    sha256_url  = _TOR_BUNDLE_URL + ".sha256sum"
    sha256_file = _TOR_DIR / "tor-expert-bundle.tar.gz.sha256sum"
    try:
        urllib.request.urlretrieve(sha256_url, sha256_file)
        expected = sha256_file.read_text(encoding="utf-8").split()[0].lower()
        actual   = hashlib.sha256(archive.read_bytes()).hexdigest().lower()
        if actual != expected:
            print("  SHA-256 mismatch — aborting for your safety.")
            archive.unlink(missing_ok=True)
            return None
        print("  SHA-256 verified.")
    except urllib.error.URLError as exc:
        print(f"  Warning: could not verify checksum ({exc}).")
    finally:
        sha256_file.unlink(missing_ok=True)

    print("  Extracting …")
    try:
        with tarfile.open(archive) as tf:
            safe = [
                m for m in tf.getmembers()
                if not os.path.isabs(m.name) and ".." not in m.name.split("/")
            ]
            tf.extractall(_TOR_DIR, members=safe)
    except Exception as exc:
        print(f"  Extraction failed: {exc}")
        return None
    finally:
        archive.unlink(missing_ok=True)

    for rel in ["Tor/tor.exe", "tor.exe"]:
        p = _TOR_DIR / rel
        if p.is_file():
            return p
    return None


def _find_geoip_files(tor_exe: Path) -> dict:
    tor_dir = tor_exe.parent
    entries: dict[str, str] = {}
    for base in [tor_dir.parent / "Data" / "Tor", tor_dir]:
        if "GeoIPFile" not in entries:
            geoip = base / "geoip"
            if geoip.is_file():
                entries["GeoIPFile"] = str(geoip)
        if "GeoIPv6File" not in entries:
            geoip6 = base / "geoip6"
            if geoip6.is_file():
                entries["GeoIPv6File"] = str(geoip6)
        if len(entries) == 2:
            break
    return entries


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _socks_port_for_tor() -> str:
    """Return ``"9050"`` if that port is free, else ``"0"``.

    When we start our own Tor process we want it to expose a SOCKS5 proxy on
    the standard port 9050 so that outbound .onion requests (e.g. mesh peer
    joins) can route through Tor without needing a separate system-level Tor
    installation.

    If port 9050 is already occupied (e.g. a system Tor daemon is running),
    return ``"0"`` to disable the SocksPort in our process — the existing
    listener at 9050 will serve SOCKS5 requests just fine.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 9050))
        return "9050"
    except OSError:
        return "0"


def _tor_log(line: str) -> None:
    if "Bootstrapped" in line or "[err]" in line.lower() or "[warn]" in line.lower():
        print(f"  [Tor] {line.rstrip()}")


def _start_tor(tor_exe: Path, server_port: int) -> tuple[str, object] | None:
    """Launch Tor with a hidden service on *server_port*.

    Returns ``(onion_address, tor_process)`` or ``None``.
    """
    try:
        import stem.process  # noqa: PLC0415
    except ImportError:
        print("  stem not installed — skipping Tor.")
        return None

    _HS_DIR.mkdir(parents=True, exist_ok=True)
    _TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)

    print("\n  Starting Tor …  (may take up to 2 min on first run)")

    config: dict = {
        "SocksPort":               _socks_port_for_tor(),
        "ControlPort":             str(_free_port()),
        "DataDirectory":           str(_TOR_DATA_DIR),
        "HiddenServiceDir":        str(_HS_DIR),
        "HiddenServicePort":       f"80 127.0.0.1:{server_port}",
        # Prevent the common "stuck at 95%" bootstrap stall.
        # Tor builds 3-hop circuits to complete bootstrap; if the first guard
        # it tries is slow the default adaptive timeout can freeze for many
        # minutes.  This value is used as the initial estimate; Tor's adaptive
        # algorithm then refines it upward.  Even with learning enabled, the
        # 10-second starting point causes rapid guard rotation early in the
        # session when circuits are most likely to stall.
        "CircuitBuildTimeout": "10",
    }
    config.update(_find_geoip_files(tor_exe))

    tor_process = None
    _tmp_data_dir: str | None = None
    last_exc: Exception | None = None
    for attempt in range(3):
        if attempt > 0:
            config["ControlPort"] = str(_free_port())
            # On retry use a fresh temp DataDirectory to avoid lock conflicts
            # (e.g. another Tor instance still holds a lock on the main data dir).
            # The .onion identity is stored in HiddenServiceDir, not DataDirectory,
            # so the .onion address is preserved across retries.
            if _tmp_data_dir is None:
                _tmp_data_dir = tempfile.mkdtemp(prefix="sc_tor_data_")
            config["DataDirectory"] = _tmp_data_dir
        try:
            launch_kwargs: dict = {
                "tor_cmd": str(tor_exe),
                "config": config,
                "init_msg_handler": _tor_log,
            }
            # stem uses signal.alarm() to implement the timeout, which is not
            # available on Windows.  Passing timeout= on Windows raises:
            #   OSError: You cannot launch tor with a timeout on Windows
            if platform.system() != "Windows":
                launch_kwargs["timeout"] = 120
            tor_process = stem.process.launch_tor_with_config(**launch_kwargs)
            break
        except OSError as exc:
            last_exc = exc
            # The Windows-timeout error is permanent; retrying is pointless.
            if "timeout on Windows" in str(exc):
                break
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"  Tor error: {exc}")
            return None

    if tor_process is None:
        if last_exc:
            print(f"  Tor failed to start: {last_exc}")
        else:
            print("  Tor failed to start.")
        return None

    hostname_file = _HS_DIR / "hostname"
    for _ in range(60):
        if hostname_file.is_file():
            onion = hostname_file.read_text(encoding="utf-8").strip()
            return onion, tor_process
        time.sleep(1)

    print("  Timed out waiting for .onion hostname.")
    tor_process.terminate()
    return None


# ---------------------------------------------------------------------------
# Step 3 — Detect LAN IP for fallback URL
# ---------------------------------------------------------------------------

def _lan_ip() -> str:
    """Best-effort detection of the machine's LAN IP address."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


# ---------------------------------------------------------------------------
# Step 3b — Local mesh hub auto-start
# ---------------------------------------------------------------------------

def _is_port_open(port: int) -> bool:
    """Return True if something is already listening on 127.0.0.1:*port*.

    Uses a 0.5-second connect timeout which is long enough to detect a local
    listener reliably while short enough not to slow down startup noticeably.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        return False


_HUB_START_TIMEOUT_SEC: float = 3.0     # max seconds to wait for hub to start
_HUB_START_POLL_INTERVAL: float = 0.1   # polling interval while waiting


def _ensure_local_mesh_hub(port: int) -> None:
    """Start the local mesh hub (local_mesh.py) in the background if not already running.

    Called automatically when ``LOCAL_MESH_PORT`` is set so operators only
    need to run ``python run.py --local-mesh-port <port>`` on each instance —
    no separate ``python local_mesh.py`` invocation is required.

    If the hub port is already occupied (another instance started it, or the
    user started it manually) this function returns immediately without
    spawning a second hub.
    """
    if _is_port_open(port):
        return  # hub already running — nothing to do

    hub_script = _HERE / "local_mesh.py"
    if not hub_script.is_file():
        print(f"  ⚠️  local_mesh.py not found next to run.py — skipping hub start.")
        return

    env = os.environ.copy()
    env["LOCAL_MESH_PORT"] = str(port)

    # Spawn the hub as a detached background process.  We use DETACHED_PROCESS
    # on Windows and start_new_session on POSIX so the hub survives the parent.
    kwargs: dict = {
        "env": env,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    try:
        subprocess.Popen([sys.executable, str(hub_script)], **kwargs)
    except OSError as exc:
        print(f"  ⚠️  Could not start local mesh hub: {exc}")
        return

    # Wait up to _HUB_START_TIMEOUT_SEC for the hub to begin accepting connections.
    _max_polls = int(_HUB_START_TIMEOUT_SEC / _HUB_START_POLL_INTERVAL)
    for _ in range(_max_polls):
        if _is_port_open(port):
            break
        time.sleep(_HUB_START_POLL_INTERVAL)
    else:
        print(f"  ⚠️  Local mesh hub on port {port} did not start in time.")
        return

    print(f"  🕸️   Local mesh hub started on port {port}.")


# ---------------------------------------------------------------------------
# Step 4 — Print startup summary
# ---------------------------------------------------------------------------

def _print_summary(
    *,
    server_port: int,
    onion: str | None,
    admin_path: str,
    admin_passcode: str,
    relay_secret: str,
    relay_enabled: bool,
    smtp_enabled: bool,
    mail_domain: str,
    mesh_token: str,
    mesh_path: str,
    local_mesh_port: int = 0,
) -> None:
    lan = _lan_ip()
    sep = "=" * 66
    base_url = f"http://{onion}" if onion else f"http://{lan}:{server_port}"

    print()
    print(sep)
    print("  🔒  secureChat is running!")
    print(sep)

    if onion:
        print()
        print("  🧅  Public .onion URL  (open in Tor Browser):")
        print()
        print(f"        http://{onion}")
        print()
        print("  Share this with the other party — it works from anywhere.")
    else:
        print()
        print("  🌐  Local / LAN access:")
        print()
        print(f"        http://{lan}:{server_port}")
        print()
        print("  Tip: install Tor (https://torproject.org) and re-run for a")
        print("       public .onion address that works from anywhere.")

    print()
    print(f"  🔐  Admin panel  (keep secret):")
    print(f"        http://127.0.0.1:{server_port}/{admin_path}/")
    print(f"        Passcode: {admin_passcode}")

    print()
    print("  📬  Inbox  (real email — any server can deliver here, no DNS needed):")
    print(f"        Open {base_url}  and click 'Inbox'")
    print("        A free @mail.tm address is auto-provisioned — share it anywhere.")
    if smtp_enabled:
        print(f"        Local SMTP: <token>@{mail_domain}  (port-25, exposes server IP)")
    if relay_enabled:
        print()
        print("  📡  IP-private relay webhook:")
        print(f"        POST {base_url}/inbox/relay")
        print(f"        X-Relay-Secret: {relay_secret}")

    print()
    print("  🕸️   Mesh / multi-device federation:")
    if local_mesh_port:
        print("        Local cluster (same machine) — hub is running on port "
              f"{local_mesh_port}.")
        print("        To add another instance on this machine:")
        print()
        print(f"        python run.py --port <other_port> --local-mesh-port {local_mesh_port}")
        print()
        print("        Remote mesh — link instances anywhere in the world:")
    else:
        print("        Run another instance anywhere in the world, then link them:")
        print()
        print("        Same-machine cluster (instant, no Tor needed):")
        print()
        print(f"        python run.py --port <other_port> --local-mesh-port 9000")
        print()
        print("          (first instance auto-starts the hub; others just join it)")
        print()
        print("        Remote mesh:")
    print()
    connect_url = f"{base_url}/{mesh_path}/mesh/connect"
    print(f"        python run.py --mesh-join {connect_url} --mesh-token {mesh_token}")
    print()
    print("        Both instances will share room messages across the mesh.")
    print("        Uses Tor (.onion) when available — no IP exposed.")

    print()
    print("  🛡️   Outbound proxy routing:")
    print("        Mail & mesh calls route through: Tor SOCKS5 → free SOCKS5 → direct")
    print("        (chat traffic goes over Tor hidden service — no proxy needed)")

    print()
    print("  Press Ctrl+C to stop.")
    print(sep)
    print()


# ---------------------------------------------------------------------------
# Mesh join helper
# ---------------------------------------------------------------------------

def _join_mesh_peer(
    *,
    connect_url: str,
    remote_token: str,
    local_token: str,
    local_mesh_path: str = "",
    onion: str | None,
    server_port: int,
) -> list[dict]:
    """POST to the remote server's /<mesh_path>/mesh/connect to register as a peer.

    When the target URL is a .onion address the request is routed through the
    local Tor SOCKS5 proxy at 127.0.0.1:9050 so hidden-service peers can be
    reached.  Up to 3 attempts are made with a short delay between each so
    that a freshly-started Tor circuit has time to become usable.

    If the Tor proxy itself is unreachable (ProxyConnectionError / connection
    refused on 127.0.0.1:9050), retrying is pointless — the function aborts
    immediately and prints a clear message asking the user to start Tor.

    For plain (non-onion) URLs the legacy urllib path is used so that there is
    no hard dependency on aiohttp / aiohttp-socks in non-Tor deployments.

    Returns a list of peer dicts (url, token, mesh_path) from the connect
    response so the caller can pre-populate ``_mesh_peers`` before the server
    starts.  Returns an empty list on failure.
    """
    import json as _json  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    if not remote_token:
        print("\n  ⚠️  --mesh-join requires --mesh-token <MESH_TOKEN of the remote server>")
        return []

    lan = _lan_ip()
    local_url = f"http://{onion}" if onion else f"http://{lan}:{server_port}"
    payload = _json.dumps({
        "token":          remote_token,
        "peer_url":       local_url,
        "peer_token":     local_token,
        "peer_mesh_path": local_mesh_path,
    }).encode()

    is_onion = ".onion" in connect_url.lower()
    max_attempts = 3
    attempt_delay = 2.0  # seconds between retries

    print(f"\n  Joining mesh peer at {connect_url} …")
    if is_onion:
        print("  (routing through Tor SOCKS5 — may take a few seconds)")

    # Derive the base URL of the target server for adding it to _mesh_peers.
    try:
        from urllib.parse import urlparse as _urlparse  # noqa: PLC0415
        _parsed = _urlparse(connect_url)
        _target_base = f"{_parsed.scheme}://{_parsed.netloc}"
    except Exception:  # noqa: BLE001
        _target_base = ""

    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            if is_onion:
                # Use aiohttp + aiohttp-socks so the request goes through Tor.
                import asyncio as _asyncio  # noqa: PLC0415
                import aiohttp as _aiohttp  # noqa: PLC0415
                from aiohttp_socks import ProxyConnector as _ProxyConnector  # noqa: PLC0415

                async def _post_via_tor() -> dict:
                    connector = _ProxyConnector.from_url("socks5://127.0.0.1:9050")
                    timeout = _aiohttp.ClientTimeout(total=30.0)
                    async with _aiohttp.ClientSession(
                        connector=connector, timeout=timeout
                    ) as sess:
                        async with sess.post(
                            connect_url,
                            data=payload,
                            headers={"Content-Type": "application/json"},
                        ) as resp:
                            if resp.status == 403:
                                raise Exception(
                                    "HTTP 403 Forbidden — wrong MESH_TOKEN. "
                                    "Check the token printed on the remote server's console."
                                )
                            if resp.status != 200:
                                body = await resp.text()
                                raise Exception(f"HTTP {resp.status}: {body[:200]}")
                            return await resp.json(content_type=None)

                data = _asyncio.run(_post_via_tor())
            else:
                import urllib.request as _urllib_request  # noqa: PLC0415
                import urllib.error as _urllib_error  # noqa: PLC0415

                req = _urllib_request.Request(
                    connect_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                try:
                    with _urllib_request.urlopen(req, timeout=15) as resp:
                        data = _json.loads(resp.read())
                except _urllib_error.HTTPError as http_err:
                    if http_err.code == 403:
                        raise Exception(
                            "HTTP 403 Forbidden — wrong MESH_TOKEN. "
                            "Check the token printed on the remote server's console."
                        ) from http_err
                    raise Exception(f"HTTP {http_err.code}: {http_err.reason}") from http_err

            if data.get("ok"):
                print(f"  ✅  Mesh peer connected  (peer_id: …{data.get('peer_id', '')[-6:]})")
                # Build the list of peers to pre-populate _mesh_peers:
                # 1. The server we just connected to.
                # 2. Any existing peers it told us about.
                peers_out: list[dict] = []
                if _target_base:
                    peers_out.append({
                        "url":       _target_base,
                        "token":     remote_token,
                        "mesh_path": data.get("mesh_path", ""),
                    })
                for _p in data.get("peers", []):
                    if _p.get("url") and _p.get("token"):
                        peers_out.append({
                            "url":       _p["url"],
                            "token":     _p["token"],
                            "mesh_path": _p.get("mesh_path", ""),
                        })
                return peers_out
            else:
                print(f"  ⚠️  Mesh join response: {data}")
            return []  # non-ok response — don't retry

        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            # If the Tor proxy itself is unreachable (not just a circuit error),
            # retrying will not help — abort immediately with a clear hint.
            if is_onion:
                _proxy_unreachable = False
                try:
                    from aiohttp_socks import ProxyConnectionError as _PCE  # noqa: PLC0415
                    _proxy_unreachable = isinstance(exc, _PCE)
                except ImportError:
                    _proxy_unreachable = "connect to proxy" in str(exc).lower()
                if _proxy_unreachable:
                    print(
                        f"  ⚠️  Tor proxy not reachable at 127.0.0.1:9050 — "
                        "start Tor before joining .onion peers."
                    )
                    return []
            if attempt < max_attempts:
                print(f"  ↻  Attempt {attempt}/{max_attempts} failed: {exc}  — retrying in {attempt_delay:.0f}s …")
                _time.sleep(attempt_delay)

    print(f"  ⚠️  Mesh join failed after {max_attempts} attempts: {last_exc}")
    return []


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    # On Windows the default ProactorEventLoop uses IOCP which can emit
    # WinError 995 ("I/O operation aborted") during aiohttp shutdown when a
    # Tor subprocess is still open, producing an unhandled-exception traceback.
    # The SelectorEventLoop is stable for all server workloads and avoids this.
    if sys.platform == "win32":
        import asyncio as _asyncio
        _asyncio.set_event_loop_policy(_asyncio.WindowsSelectorEventLoopPolicy())

    parser = argparse.ArgumentParser(
        description="secureChat zero-config launcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Environment variable reference: info-files/env-vars.md\nFull option descriptions: info-files/start-server-config.md",
    )
    # Server
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--db-path", metavar="PATH", default=None)
    # Custom URL paths / secrets
    parser.add_argument("--clearnet-path", metavar="PATH", default=None)
    parser.add_argument("--admin-path", metavar="PATH", default=None)
    parser.add_argument("--admin-passcode", metavar="SECRET", default=None)
    parser.add_argument("--admin-webhook-token", metavar="TOKEN", default=None)
    # Tor
    parser.add_argument("--no-tor", action="store_true", default=None)
    parser.add_argument("--tor-path", metavar="PATH", default=None)
    parser.add_argument("--onion-address", metavar="HOSTNAME", default=None)
    # Mesh
    parser.add_argument("--mesh-join", metavar="URL", default=None)
    parser.add_argument("--mesh-token", metavar="TOKEN", default=None)
    # Mail / SMTP
    parser.add_argument("--mail-domain", metavar="DOMAIN", default=None)
    parser.add_argument("--smtp-port", type=int, default=None)
    parser.add_argument("--relay-secret", metavar="SECRET", default=None)
    # Misc
    parser.add_argument("--auto-update", action="store_true", default=None)
    parser.add_argument("--slow-mode", action="store_true", default=None)
    parser.add_argument("--slow-mode-delay", type=float, metavar="SECONDS", default=None)
    # DDoS protection
    parser.add_argument("--ddos-enabled", type=int, metavar="0|1", default=None)
    parser.add_argument("--ddos-req-limit", type=int, metavar="N", default=None)
    parser.add_argument("--ddos-window-sec", type=int, metavar="N", default=None)
    parser.add_argument("--ddos-ban-sec", type=int, metavar="N", default=None)
    parser.add_argument("--ddos-auto-lockdown-threshold", type=int, metavar="N", default=None)
    # Spam protection
    parser.add_argument("--spam-enabled", type=int, metavar="0|1", default=None)
    parser.add_argument("--spam-msg-limit", type=int, metavar="N", default=None)
    parser.add_argument("--spam-msg-window", type=int, metavar="N", default=None)
    parser.add_argument("--spam-mail-limit", type=int, metavar="N", default=None)
    parser.add_argument("--spam-mail-window", type=int, metavar="N", default=None)
    # Chat history
    parser.add_argument("--history-limit", type=int, metavar="N", default=None)
    # mail.tm integration
    parser.add_argument("--mailtm-enabled", type=int, metavar="0|1", default=None)
    # Local mesh (multi-instance on same machine)
    parser.add_argument("--local-mesh-port", type=int, metavar="PORT", default=None)
    parser.add_argument("--file-storage", metavar="PATH", default=None)
    # .env helper
    parser.add_argument(
        "--example",
        action="store_true",
        help="Copy .env.example to .env and exit. See info-files/env-vars.md for documentation.",
    )
    # URL reset helpers — clear persisted values so fresh ones are generated
    parser.add_argument(
        "--new-mesh-url",
        action="store_true",
        default=False,
        help=(
            "Generate a new random mesh URL for this installation. "
            "Clears MESH_PATH and MESH_LOCK from .env / start_server.bat so a "
            "fresh path is created on this startup. "
            "Existing mesh peers will need to reconnect using the new URL."
        ),
    )
    parser.add_argument(
        "--new-onion-url",
        action="store_true",
        default=False,
        help=(
            "Generate a new .onion address and clearnet URL. "
            "Deletes the Tor hidden-service key directory (tor_hs/) so Tor "
            "creates a brand-new .onion address, and clears CLEARNET_PATH "
            "from .env / start_server.bat so a fresh path is also generated."
        ),
    )
    args = parser.parse_args()

    # Handle --example early, before any other startup logic.
    if args.example:
        src = _HERE / ".env.example"
        dst = _DOTENV
        if not src.is_file():
            print("  ERROR: .env.example not found next to run.py.")
            sys.exit(1)
        if dst.is_file():
            print(f"  .env already exists at: {dst}")
            print("  To regenerate it, delete .env first and re-run:  python run.py --example")
        else:
            shutil.copy2(src, dst)
            print(f"  Created .env at: {dst}")
            print("  Edit .env, uncomment the lines you want, then run:  python run.py")
        print("  Documentation:  info-files/env-vars.md")
        sys.exit(0)

    # Handle --new-mesh-url: remove stored mesh path so a new one is generated.
    if args.new_mesh_url:
        _remove_keys_from_config({"MESH_PATH", "MESH_LOCK"})
        os.environ.pop("MESH_PATH", None)
        os.environ.pop("MESH_LOCK", None)
        print("  ✅  Mesh URL cleared — a new URL will be generated on this startup.")

    # Handle --new-onion-url: delete Tor hidden-service key + clear clearnet path.
    if args.new_onion_url:
        _remove_keys_from_config({"CLEARNET_PATH"})
        os.environ.pop("CLEARNET_PATH", None)
        if _HS_DIR.is_dir():
            try:
                shutil.rmtree(_HS_DIR)
                print(
                    "  ✅  Tor hidden-service directory deleted — "
                    "a new .onion address will be created when Tor starts."
                )
            except OSError as _e:
                print(f"  ⚠️  Could not delete {_HS_DIR}: {_e}")
        else:
            print("  ✅  Clearnet URL cleared — a new URL will be generated on this startup.")

    # Save our own persisted MESH_TOKEN BEFORE _flag_env runs — the --mesh-token
    # flag writes the REMOTE server's token into os.environ["MESH_TOKEN"], which
    # would overwrite our own persisted value if we read it after the loop.
    _own_persisted_mesh_token = os.environ.get("MESH_TOKEN", "").strip()

    # Apply CLI flags to env vars (only when explicitly provided, so .env and
    # parent-process env vars are not overridden by argparse defaults).
    _flag_env: list[tuple[object, str]] = [
        (args.port,                          "PORT"),
        (args.host,                          "HOST"),
        (args.db_path,                       "DB_PATH"),
        (args.clearnet_path,                 "CLEARNET_PATH"),
        (args.admin_path,                    "ADMIN_PATH"),
        (args.admin_passcode,                "ADMIN_PASSCODE"),
        (args.admin_webhook_token,           "ADMIN_WEBHOOK_TOKEN"),
        (args.tor_path,                      "TOR_PATH"),
        (args.onion_address,                 "ONION_ADDRESS"),
        (args.mesh_join,                     "MESH_JOIN"),
        (args.mesh_token,                    "MESH_TOKEN"),
        (args.mail_domain,                   "MAIL_DOMAIN"),
        (args.smtp_port,                     "SMTP_PORT"),
        (args.relay_secret,                  "RELAY_SECRET"),
        (args.slow_mode_delay,               "SLOW_MODE_DELAY"),
        (args.ddos_enabled,                  "DDOS_ENABLED"),
        (args.ddos_req_limit,                "DDOS_REQ_LIMIT"),
        (args.ddos_window_sec,               "DDOS_WINDOW_SEC"),
        (args.ddos_ban_sec,                  "DDOS_BAN_SEC"),
        (args.ddos_auto_lockdown_threshold,  "DDOS_AUTO_LOCKDOWN_THRESHOLD"),
        (args.spam_enabled,                  "SPAM_ENABLED"),
        (args.spam_msg_limit,                "SPAM_MSG_LIMIT"),
        (args.spam_msg_window,               "SPAM_MSG_WINDOW"),
        (args.spam_mail_limit,               "SPAM_MAIL_LIMIT"),
        (args.spam_mail_window,              "SPAM_MAIL_WINDOW"),
        (args.history_limit,                 "HISTORY_LIMIT"),
        (args.mailtm_enabled,                "MAILTM_ENABLED"),
        (args.local_mesh_port,               "LOCAL_MESH_PORT"),
        (args.file_storage,                  "FILE_STORAGE"),
    ]
    for val, key in _flag_env:
        if val is not None:
            os.environ[key] = str(val)
    if args.no_tor:
        os.environ["NO_TOR"] = "1"
    if args.auto_update:
        os.environ["AUTO_UPDATE"] = "1"
    if args.slow_mode:
        os.environ["SLOW_MODE"] = "1"

    server_port: int = args.port if args.port is not None else int(os.environ.get("PORT", "5000"))

    print()
    print("=" * 66)
    print("  secureChat — zero-config launcher")
    print("=" * 66)
    print()

    # ── 0. Auto-update (git pull) if enabled ─────────────────────────
    _auto_update()

    # ── 1. Dependencies ──────────────────────────────────────────────
    _ensure_dependencies()

    # ── 2. Set environment variables before importing server ─────────
    os.environ.setdefault("PORT", str(server_port))

    # Auto-generate RELAY_SECRET if not already set
    relay_secret = os.environ.get("RELAY_SECRET", "")
    relay_was_set = bool(relay_secret)
    if not relay_secret:
        relay_secret = secrets.token_urlsafe(32)
        # We print the generated secret in the summary but do NOT auto-enable
        # the endpoint (user must consciously set it in their relay service).
        # Setting it here activates the /inbox/relay route for this session.
        os.environ["RELAY_SECRET"] = relay_secret
    relay_enabled = True  # always enabled once we've set the env var

    # ── 3. Tor ───────────────────────────────────────────────────────
    onion: str | None = None
    tor_process = None

    skip_tor = args.no_tor or (os.environ.get("NO_TOR", "").strip() in ("1", "true", "yes"))
    if not skip_tor:
        print()
        tor_exe = _find_tor()
        if not tor_exe:
            print("  Tor not found — trying to download (Windows only) …")
            tor_exe = _download_tor_windows()

        if tor_exe:
            result = _start_tor(tor_exe, server_port)
            if result:
                onion, tor_process = result
                os.environ.setdefault("HOST", "127.0.0.1")
                print(f"\n  ✅  .onion address ready: {onion}")
            else:
                print("  ⚠️  Tor hidden service failed — falling back to LAN access.")
        else:
            print("  Tor not available — using LAN access.")
            print("  Install Tor from https://torproject.org for a public .onion address.")
            print("  On Linux: sudo apt install tor  /  brew install tor  (macOS)")
            print(f"  Or set TOR_PATH=/path/to/tor in your .env file.")

    if not onion:
        # No Tor — bind to all interfaces so LAN devices can connect
        os.environ.setdefault("HOST", "0.0.0.0")

    # ── 3b. Local mesh hub ────────────────────────────────────────────
    local_mesh_port: int = int(os.environ.get("LOCAL_MESH_PORT", "0"))
    if local_mesh_port:
        _ensure_local_mesh_hub(local_mesh_port)

    # ── 4. Import server (now dependencies are guaranteed to be present) ──
    # We must import AFTER pip-installing, and AFTER setting env vars.
    try:
        import server as srv  # noqa: PLC0415
    except ImportError as exc:
        print(f"\n  ERROR: could not import server.py — {exc}")
        sys.exit(1)

    from aiohttp import web  # noqa: PLC0415

    # ── 5. Initialise admin credentials in this process ──────────────
    import secrets as _secrets  # noqa: PLC0415

    # Initialise credentials in the server module's globals directly so
    # build_app() picks them up without a second initialisation.
    srv._ADMIN_PATH, srv._ADMIN_PASSCODE = srv._init_admin_credentials()
    srv._ADMIN_WEBHOOK_TOKEN = _secrets.token_urlsafe(32)
    # Re-use our own persisted MESH_TOKEN (saved before _flag_env could
    # overwrite MESH_TOKEN with the remote server's token).  Generate a
    # fresh one only on the very first run when nothing is persisted yet.
    srv._MESH_TOKEN = _own_persisted_mesh_token or _secrets.token_urlsafe(32)
    srv._MESH_PATH  = srv._init_mesh_path()
    srv._CLEARNET_PATH = srv._init_clearnet_path()

    # Persist auto-generated secrets so they survive restarts.
    # On Windows the .bat launcher is updated with SET commands so the values
    # are available before Python starts.  On other platforms (or when the bat
    # file is absent) the secrets fall back to the .env file.
    # Admin path and passcode are intentionally NOT persisted — they are
    # regenerated on every startup so credentials never stay the same.
    # MESH_LOCK ties the stored MESH_PATH to this installation folder; it is
    # always overwritten so a copied .env / .bat gets its lock corrected on
    # the very next run and triggers path regeneration for the new folder.
    _secrets_to_persist = {
        "CLEARNET_PATH":       srv._CLEARNET_PATH,
        "ADMIN_WEBHOOK_TOKEN": srv._ADMIN_WEBHOOK_TOKEN,
        "MESH_TOKEN":          srv._MESH_TOKEN,
        "MESH_PATH":           srv._MESH_PATH,
        "MESH_LOCK":           srv._folder_lock(),
    }
    _mesh_overwrite = frozenset({"MESH_PATH", "MESH_LOCK"})
    wrote_bat = srv._persist_vars_to_bat(_secrets_to_persist, overwrite_keys=_mesh_overwrite)
    if not wrote_bat:
        # Fallback: write to .env for non-Windows or missing bat file.
        srv._persist_new_env_vars(_secrets_to_persist, overwrite_keys=_mesh_overwrite)

    mail_domain: str = srv.MAIL_DOMAIN
    smtp_enabled: bool = bool(mail_domain)

    # ── 6. Print startup summary ─────────────────────────────────────
    _print_summary(
        server_port=server_port,
        onion=onion,
        admin_path=srv._ADMIN_PATH,
        admin_passcode=srv._ADMIN_PASSCODE,
        relay_secret=relay_secret,
        relay_enabled=True,
        smtp_enabled=smtp_enabled,
        mail_domain=mail_domain,
        mesh_token=srv._MESH_TOKEN,
        mesh_path=srv._MESH_PATH,
        local_mesh_port=local_mesh_port,
    )

    # ── 7. Run the server ─────────────────────────────────────────────
    host = os.environ.get("HOST", "127.0.0.1")

    # ── 8. Join a remote mesh peer (optional) ─────────────────────────
    mesh_join_url = os.environ.get("MESH_JOIN", "")
    if mesh_join_url:
        import time as _time_mod  # noqa: PLC0415
        joined_peers = _join_mesh_peer(
            connect_url=mesh_join_url,
            remote_token=os.environ.get("MESH_TOKEN", ""),
            local_token=srv._MESH_TOKEN,
            local_mesh_path=srv._MESH_PATH,
            onion=onion,
            server_port=server_port,
        )
        # Populate _mesh_peers with every peer the remote server told us about
        # (includes the remote server itself and any peers it already has).
        # This ensures we can forward messages to all of them immediately.
        import secrets as _sec2  # noqa: PLC0415
        for _p in joined_peers:
            if _p.get("url") and _p.get("token"):
                srv._mesh_peers[_sec2.token_hex(16)] = {
                    "url":          _p["url"],
                    "token":        _p["token"],
                    "mesh_path":    _p.get("mesh_path", ""),
                    "connected_at": _time_mod.time(),
                }

    try:
        web.run_app(srv.build_app(), host=host, port=server_port, access_log=None)
    except (KeyboardInterrupt, SystemExit):
        pass
    except OSError as exc:
        print(f"\n  ⚠️  Cannot start server: {exc}")
        print(f"  Is another process already using port {server_port}?")
    except RuntimeError as exc:
        # On Windows the ProactorEventLoop can raise RuntimeError("Event loop is
        # closed") during aiohttp's asyncio cleanup when a Tor subprocess is still
        # open.  The SelectorEventLoop policy set above prevents this, but catch
        # it here as a safety net for any remaining edge cases.
        print(f"\n  ⚠️  Server stopped with an error: {exc}")
    finally:
        if tor_process is not None:
            try:
                tor_process.terminate()
            except Exception:  # noqa: BLE001
                pass
        print("\n  Server stopped.  Goodbye!")


if __name__ == "__main__":
    main()
