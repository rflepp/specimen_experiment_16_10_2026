"""Publish site/ to docs/ behind a password.

Every file of the plaintext site (page, code, data, videos) is encrypted with AES-256-GCM
under a key derived from the password (PBKDF2-SHA256) and written to docs/x/ under an opaque
name. docs/index.html is only a lock screen (tools/lock.html) that derives the same key in
the browser, decrypts the file index and then the page. Without the password the published
repository contains no readable content.

usage:  python tools/encrypt_site.py          (asks for the password; or set SITE_PASSWORD)
"""
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "site"
OUT = ROOT / "docs"
ENC = OUT / "x"
ITERATIONS = 600_000
TYPES = {".html": "text/html", ".css": "text/css", ".js": "text/javascript", ".json": "application/json",
         ".mp4": "video/mp4", ".svg": "image/svg+xml", ".png": "image/png"}


def main():
    # the password is case-insensitive: the lock screen lowercases input the same way
    password = (os.environ.get("SITE_PASSWORD") or getpass.getpass("Password: ")).lower()
    # reuse the previous build's salt so unchanged files encrypt to identical bytes (no repo bloat on rebuilds)
    lock = OUT / "index.html"
    found = re.search(r'data-salt="([0-9a-f]{32})"', lock.read_text(encoding="utf-8")) if lock.exists() else None
    salt = bytes.fromhex(found[1]) if found else secrets.token_bytes(16)

    # first 32 bytes: AES key (the browser derives only these); next 32: key for names and nonces
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS, 64)
    aes, mac_key = AESGCM(derived[:32]), derived[32:]

    def mac(data):
        return hmac.new(mac_key, data, "sha256").digest()

    def seal(data):
        # nonce from the content: identical files give identical output, different files never share a nonce
        nonce = mac(data)[:12]
        return nonce + aes.encrypt(nonce, data, None)

    shutil.rmtree(ENC, ignore_errors=True)
    ENC.mkdir(parents=True)
    files = {}
    for path in sorted(p for p in SRC.rglob("*") if p.is_file()):
        rel = path.relative_to(SRC).as_posix()
        name = mac(rel.encode()).hex()[:24]
        (ENC / name).write_bytes(seal(path.read_bytes()))
        files[rel] = {"f": name, "type": TYPES.get(path.suffix, "application/octet-stream")}
    (ENC / "m").write_bytes(seal(json.dumps(files).encode()))

    page = (ROOT / "tools" / "lock.html").read_text(encoding="utf-8")
    lock.write_text(page.replace("{{SALT}}", salt.hex()).replace("{{ITERATIONS}}", str(ITERATIONS)), encoding="utf-8")
    (OUT / ".nojekyll").touch()
    size = sum(p.stat().st_size for p in ENC.iterdir()) / 1e6
    print(f"encrypted {len(files)} files ({size:.1f} MB) to {ENC.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
