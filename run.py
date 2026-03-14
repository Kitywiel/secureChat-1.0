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
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve paths
# ---------------------------------------------------------------------------
_HERE = Path(__file__).resolve().parent
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

    print("\n  Starting Tor …  (may take up to 90 s on first run)")

    config: dict = {
        "SocksPort":        "0",
        "ControlPort":      str(_free_port()),
        "DataDirectory":    str(_TOR_DATA_DIR),
        "HiddenServiceDir": str(_HS_DIR),
        "HiddenServicePort": f"80 127.0.0.1:{server_port}",
    }
    config.update(_find_geoip_files(tor_exe))

    tor_process = None
    for attempt in range(3):
        if attempt > 0:
            config["ControlPort"] = str(_free_port())
        try:
            tor_process = stem.process.launch_tor_with_config(
                tor_cmd=str(tor_exe),
                config=config,
                timeout=90,
                init_msg_handler=_tor_log,
            )
            break
        except OSError:
            continue
        except Exception as exc:  # noqa: BLE001
            print(f"  Tor error: {exc}")
            return None

    if tor_process is None:
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
    print("        Run another instance anywhere in the world, then link them:")
    print()
    print(f"        python run.py --mesh-join {base_url}/mesh/peer/connect --mesh-token {mesh_token}")
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
    onion: str | None,
    server_port: int,
) -> None:
    """POST to the remote server's /mesh/peer/connect to register as a peer.

    When the target URL is a .onion address the request is routed through the
    local Tor SOCKS5 proxy at 127.0.0.1:9050 so hidden-service peers can be
    reached.  Up to 3 attempts are made with a short delay between each so
    that a freshly-started Tor circuit has time to become usable.

    For plain (non-onion) URLs the legacy urllib path is used so that there is
    no hard dependency on aiohttp / aiohttp-socks in non-Tor deployments.
    """
    import json as _json  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    if not remote_token:
        print("\n  ⚠️  --mesh-join requires --mesh-token <MESH_TOKEN of the remote server>")
        return

    lan = _lan_ip()
    local_url = f"http://{onion}" if onion else f"http://{lan}:{server_port}"
    payload = _json.dumps({
        "token":      remote_token,
        "peer_url":   local_url,
        "peer_token": local_token,
    }).encode()

    is_onion = ".onion" in connect_url.lower()
    max_attempts = 3
    attempt_delay = 2.0  # seconds between retries

    print(f"\n  Joining mesh peer at {connect_url} …")
    if is_onion:
        print("  (routing through Tor SOCKS5 — may take a few seconds)")

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
                            return await resp.json()

                data = _asyncio.run(_post_via_tor())
            else:
                import urllib.request as _urllib_request  # noqa: PLC0415

                req = _urllib_request.Request(
                    connect_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with _urllib_request.urlopen(req, timeout=15) as resp:
                    data = _json.loads(resp.read())

            if data.get("ok"):
                print(f"  ✅  Mesh peer connected  (peer_id: …{data.get('peer_id', '')[-6:]})")
            else:
                print(f"  ⚠️  Mesh join response: {data}")
            return  # success — stop retrying

        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < max_attempts:
                print(f"  ↻  Attempt {attempt}/{max_attempts} failed: {exc}  — retrying in {attempt_delay:.0f}s …")
                _time.sleep(attempt_delay)

    print(f"  ⚠️  Mesh join failed after {max_attempts} attempts: {last_exc}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="secureChat zero-config launcher")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "5000")))
    parser.add_argument(
        "--no-tor",
        action="store_true",
        default=(os.environ.get("NO_TOR", "").strip() in ("1", "true", "yes")),
        help="Skip Tor even if installed",
    )
    parser.add_argument(
        "--mesh-join",
        metavar="URL",
        default=os.environ.get("MESH_JOIN", ""),
        help="Connect to a remote peer's /mesh/peer/connect URL",
    )
    parser.add_argument(
        "--mesh-token",
        metavar="TOKEN",
        default=os.environ.get("MESH_TOKEN", ""),
        help="MESH_TOKEN of the remote server (required with --mesh-join)",
    )
    args = parser.parse_args()

    server_port: int = args.port

    print()
    print("=" * 66)
    print("  secureChat — zero-config launcher")
    print("=" * 66)
    print()

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
    srv._MESH_TOKEN = _secrets.token_urlsafe(32)

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
    )

    # ── 7. Run the server ─────────────────────────────────────────────
    host = os.environ.get("HOST", "127.0.0.1")

    # ── 8. Join a remote mesh peer (optional) ─────────────────────────
    if args.mesh_join:
        _join_mesh_peer(
            connect_url=args.mesh_join,
            remote_token=args.mesh_token,
            local_token=srv._MESH_TOKEN,
            onion=onion,
            server_port=server_port,
        )

    try:
        web.run_app(srv.build_app(), host=host, port=server_port, access_log=None)
    except KeyboardInterrupt:
        pass
    finally:
        if tor_process is not None:
            try:
                tor_process.terminate()
            except Exception:  # noqa: BLE001
                pass
        print("\n  Server stopped.  Goodbye!")


if __name__ == "__main__":
    main()
