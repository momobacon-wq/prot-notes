# -*- coding: utf-8 -*-
"""Seal a plaintext JSON (kept OUTSIDE this repo) into docs/data/db.json.bin + docs/data/meta.json, then verify.

  py tools/build.py <plain.json>            # encrypt + verify
  py tools/build.py --verify                # verify only (decrypt what is in docs/data)

Scheme: key = PBKDF2-HMAC-SHA256(passphrase, salt, ITER) -> AES-256-GCM
        blob = 12-byte IV || AES-GCM(gzip(JSON)), AAD = relative name ("db.json"); meta.check seals b"ok" with AAD "check".
Key file: %LOCALAPPDATA%\\prot-notes\\web.key  (line 1 passphrase, line 2 base64 salt; created on first run).
Nothing readable is ever written under the repo.
"""
import sys, os, json, gzip, base64, hashlib, secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.stdout.reconfigure(encoding="utf-8")
ITER = 600000
ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "docs" / "data"
KEYF = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "prot-notes" / "web.key"
REL = "db.json"
ALPHA = "abcdefghjkmnpqrstuvwxyz23456789"


def key_material():
    KEYF.parent.mkdir(parents=True, exist_ok=True)
    lines = KEYF.read_text(encoding="utf-8").splitlines() if KEYF.exists() else []
    changed = False
    if not lines or not lines[0].strip():
        pw = "-".join("".join(secrets.choice(ALPHA) for _ in range(5)) for _ in range(5))
        lines = [pw] + lines[1:]
        changed = True
    if len(lines) < 2 or not lines[1].strip():
        lines = [lines[0], base64.b64encode(secrets.token_bytes(16)).decode()]
        changed = True
    if changed:
        KEYF.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    return lines[0].strip(), base64.b64decode(lines[1].strip())


def derive(pw, salt, it=ITER):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode("utf-8"))


def seal(key, plain, aad):
    iv = secrets.token_bytes(12)
    return iv + AESGCM(key).encrypt(iv, plain, aad.encode())


def unseal(key, blob, aad):
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad.encode())


def verify():
    pw, _ = key_material()
    meta = json.loads((DATA / "meta.json").read_text(encoding="utf-8"))
    key = derive(pw, base64.b64decode(meta["kdf"]["salt"]), meta["kdf"]["iter"])
    assert unseal(key, base64.b64decode(meta["check"]), "check") == b"ok"
    obj = json.loads(gzip.decompress(unseal(key, (DATA / (REL + ".bin")).read_bytes(), REL)))
    try:
        unseal(derive(pw + "x", base64.b64decode(meta["kdf"]["salt"]), meta["kdf"]["iter"]), base64.b64decode(meta["check"]), "check")
        raise SystemExit("wrong key accepted")
    except SystemExit:
        raise
    except Exception:
        pass
    print(f"[verify] ok  rows={len(obj.get('rows', []))}  build={meta['build']}")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    if sys.argv[1] != "--verify":
        src = Path(sys.argv[1]).resolve()
        if ROOT in src.parents:
            raise SystemExit("plaintext must live outside the repo")
        raw = json.dumps(json.loads(src.read_text(encoding="utf-8")), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        pw, salt = key_material()
        key = derive(pw, salt)
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / (REL + ".bin")).write_bytes(seal(key, gzip.compress(raw, 6, mtime=0), REL))
        meta = {"enc": 1, "gzip": 1, "build": hashlib.sha256(raw).hexdigest()[:10],
                "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iter": ITER, "salt": base64.b64encode(salt).decode()},
                "check": base64.b64encode(seal(key, b"ok", "check")).decode()}
        (DATA / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
        print(f"[encrypt] {len(raw)} bytes -> {(DATA / (REL + '.bin')).stat().st_size} bytes")
    verify()


if __name__ == "__main__":
    main()
