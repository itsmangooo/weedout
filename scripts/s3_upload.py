#!/usr/bin/env python3
"""Upload one file to an S3-compatible bucket. Standard library only.

    python3 scripts/s3_upload.py /path/to/weedout-20260818T031500Z.sql.gz

Configured entirely from the environment:

    BACKUP_S3_BUCKET              required; the bucket name
    BACKUP_S3_ENDPOINT            required for non-AWS (R2, MinIO, B2)
    BACKUP_S3_ACCESS_KEY_ID       required
    BACKUP_S3_SECRET_ACCESS_KEY   required
    BACKUP_S3_PREFIX              key prefix, default "weedout"
    BACKUP_S3_REGION              default "auto" (what Cloudflare R2 documents)

`boto3` would be the obvious way to do this, and it is ~50 MB of dependency for
a single PUT. This is one signed request against a well-specified algorithm, so
it is implemented directly rather than pulling the whole AWS SDK into an image
whose job is scanning lockfiles.

The signing is SigV4 with `UNSIGNED-PAYLOAD` deliberately avoided: the body
hash is computed for real, which means a file corrupted in transit is rejected
by the server rather than stored as a backup that cannot be restored.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

ALGORITHM = "AWS4-HMAC-SHA256"
SERVICE = "s3"

#: Read in chunks so a multi-gigabyte dump is never held in memory.
CHUNK = 1024 * 1024


class UploadError(Exception):
    """The upload could not be made or was refused."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signing_key(secret: str, date_stamp: str, region: str, service: str = SERVICE) -> bytes:
    """Derive the SigV4 signing key.

    Four chained HMACs, each keyed by the previous result. Split out so the
    derivation can be checked against AWS's published test vectors without
    making a network call.
    """
    key = _sign(f"AWS4{secret}".encode(), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    return _sign(key, "aws4_request")


def build_request(
    *,
    bucket: str,
    endpoint: str,
    key_name: str,
    access_key: str,
    secret_key: str,
    region: str,
    payload_hash: str,
    content_length: int,
    now: datetime | None = None,
) -> tuple[str, dict[str, str]]:
    """Return the URL and signed headers for a single PUT.

    Separated from the transfer itself so the signature can be tested without
    a server: given a fixed timestamp the output is deterministic.
    """
    now = now or datetime.now(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    scheme, _, host_and_path = endpoint.partition("://")
    if not scheme or not host_and_path:
        raise UploadError(f"BACKUP_S3_ENDPOINT must include a scheme: {endpoint!r}")
    host = host_and_path.split("/", 1)[0]

    # Path-style addressing (`/bucket/key`) rather than virtual-host style.
    # R2, MinIO and AWS all accept it, and it avoids the bucket-name-in-DNS
    # rules that virtual-host style imposes.
    canonical_uri = f"/{bucket}/{key_name}"

    canonical_headers = (
        f"content-length:{content_length}\n"
        f"host:{host}\n"
        f"x-amz-content-sha256:{payload_hash}\n"
        f"x-amz-date:{amz_date}\n"
    )
    signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date"

    canonical_request = "\n".join(
        ["PUT", canonical_uri, "", canonical_headers, signed_headers, payload_hash]
    )

    scope = f"{date_stamp}/{region}/{SERVICE}/aws4_request"
    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )

    signature = hmac.new(
        signing_key(secret_key, date_stamp, region),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Authorization": authorization,
        "Content-Length": str(content_length),
        "Host": host,
        "x-amz-content-sha256": payload_hash,
        "x-amz-date": amz_date,
        "Content-Type": "application/gzip",
    }
    return f"{scheme}://{host}{canonical_uri}", headers


def upload(path: Path, env: dict[str, str] | None = None) -> str:
    """Upload `path`. Returns the object key. Raises `UploadError` on failure."""
    env = os.environ if env is None else env

    bucket = env.get("BACKUP_S3_BUCKET", "").strip()
    endpoint = env.get("BACKUP_S3_ENDPOINT", "").strip()
    access_key = env.get("BACKUP_S3_ACCESS_KEY_ID", "").strip()
    secret_key = env.get("BACKUP_S3_SECRET_ACCESS_KEY", "").strip()
    prefix = env.get("BACKUP_S3_PREFIX", "weedout").strip().strip("/")
    region = env.get("BACKUP_S3_REGION", "auto").strip() or "auto"

    missing = [
        name
        for name, value in (
            ("BACKUP_S3_BUCKET", bucket),
            ("BACKUP_S3_ENDPOINT", endpoint),
            ("BACKUP_S3_ACCESS_KEY_ID", access_key),
            ("BACKUP_S3_SECRET_ACCESS_KEY", secret_key),
        )
        if not value
    ]
    if missing:
        raise UploadError(f"missing configuration: {', '.join(missing)}")

    if not path.is_file():
        raise UploadError(f"no such file: {path}")

    key_name = f"{prefix}/{path.name}" if prefix else path.name
    url, headers = build_request(
        bucket=bucket,
        endpoint=endpoint,
        key_name=key_name,
        access_key=access_key,
        secret_key=secret_key,
        region=region,
        payload_hash=_sha256_file(path),
        content_length=path.stat().st_size,
    )

    with path.open("rb") as body:
        request = urllib.request.Request(  # noqa: S310 - scheme checked below
            url=url, data=body, method="PUT", headers=headers
        )
        if request.type not in ("http", "https"):
            raise UploadError(f"unsupported scheme: {request.type}")
        try:
            with urllib.request.urlopen(request, timeout=600) as response:  # noqa: S310
                if response.status not in (200, 201):
                    raise UploadError(f"unexpected status {response.status}")
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:400].decode("utf-8", "replace")
            raise UploadError(f"HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise UploadError(f"could not reach {url}: {exc.reason}") from exc

    return key_name


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <file>", file=sys.stderr)
        return 2
    try:
        key = upload(Path(argv[1]))
    except UploadError as exc:
        print(f"s3_upload: {exc}", file=sys.stderr)
        return 1
    print(f"s3_upload: stored {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
