from __future__ import annotations

import base64
import gzip
import hashlib
import io
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "b11381ffb74eb956a44bba725947830d4602f143f96962515156cff8ed4c48a6"


def materialize() -> None:
    encoded = "".join(
        (ROOT / f"tools/nxb145_payload_{index:02d}.txt").read_text(encoding="utf-8").strip()
        for index in range(4)
    )
    archive = base64.b64decode(encoded, validate=True)
    if hashlib.sha256(archive).hexdigest() != EXPECTED_SHA256:
        raise SystemExit("NXB-145 payload digest mismatch")
    with tarfile.open(fileobj=gzip.GzipFile(fileobj=io.BytesIO(archive)), mode="r:") as bundle:
        for member in bundle.getmembers():
            target = (ROOT / member.name).resolve()
            if ROOT.resolve() not in target.parents:
                raise SystemExit("unsafe NXB-145 payload path")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise SystemExit("unsafe NXB-145 payload member type")
            source = bundle.extractfile(member)
            if source is None:
                raise SystemExit("missing NXB-145 payload content")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
    cargo = ROOT / "Cargo.toml"
    text = cargo.read_text(encoding="utf-8")
    member = '    "crates/nxb-live-run-host",\n'
    if member not in text:
        anchor = '    "crates/nxb-live-adapter",\n'
        if anchor not in text:
            raise SystemExit("NXB-145 workspace anchor missing")
        cargo.write_text(text.replace(anchor, anchor + member, 1), encoding="utf-8")


if __name__ == "__main__":
    materialize()
