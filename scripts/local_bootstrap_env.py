#!/usr/bin/env python3
"""Create local/CI provider-bootstrap secrets without provisioning authority.

ADR-IAM-0031/0033 keep Keycloak, Kratos, Hydra and Control Plane administration
separate. This tool prepares the local Keycloak/Postgres stack only; a password
file is neither an IAM identity nor a CP administrative grant. Native Baobab
human accounts remain Kratos-owned, with canonical identity/privilege in CP.

The secret file is deliberately generated at the execution site, never checked
into Git, printed, overwritten, or uploaded as CI evidence. Publication uses a
private same-directory temporary file followed by an exclusive hard link, so a
consumer never sees a partially written file and an existing credential is not
silently rotated. Linux/POSIX permissions are required; unsupported hosts fail.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import secrets
import stat
import sys


class SafeParser(argparse.ArgumentParser):
    """Reject invalid CLI arguments without echoing potentially secret values."""

    def error(self, message: str) -> None:
        self.exit(2, "Invalid bootstrap arguments; use --help for supported options.\n")


def create_local_env(output: Path, username: str, environment: str) -> None:
    """Atomically publish fresh local secrets in an owner-controlled directory.

    Identifiers use a closed grammar because the result is both Compose dotenv
    input and shell-readable local configuration. Passwords are URL-safe random
    tokens with an explicit 32-byte entropy input, not one shared deterministic
    seed. Never include BOOTSTRAP_WORKLOAD_CLIENT_SECRET: provider clients get
    their own secrets; the existing deterministic test seed is CI-only input.
    """
    if environment not in {"local", "ci"}:
        raise ValueError("Only isolated local/CI preparation is supported")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", username):
        raise ValueError("Invalid bootstrap username")
    if output.name not in {".env", ".env.local"}:
        raise ValueError("Output must use a gitignored dotenv filename")

    # Pin the actual directory inode for all subsequent operations. Refuse a
    # symlinked final parent, a foreign owner, and group/world-writable parents;
    # otherwise another user could replace an output or its temporary path.
    directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary: str | None = None
    try:
        parent = os.fstat(directory)
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
            raise ValueError("Credential directory is not owner controlled")
        password = secrets.token_urlsafe(32)
        database_password = secrets.token_urlsafe(32)
        content = (
            "# Generated local/CI provider bootstrap input; no platform authority.\n"
            f"BAOBAB_ENVIRONMENT={environment}\n"
            f"KEYCLOAK_ADMIN={username}\n"
            f"KEYCLOAK_ADMIN_PASSWORD={password}\n"
            "POSTGRES_USER=baobab_iam\n"
            f"POSTGRES_PASSWORD={database_password}\n"
            "POSTGRES_DB=baobab_iam\n"
        ).encode("ascii")
        candidate = ".bootstrap-env-" + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        temporary = candidate
        try:
            # fchmod preserves the required mode even with an unusual umask.
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(fd)
            # link() never replaces an existing file or symlink. The published
            # inode already contains the full configuration with mode 0600.
            os.link(temporary, output.name, src_dir_fd=directory,
                    dst_dir_fd=directory, follow_symlinks=False)
            os.fsync(directory)
        finally:
            os.close(fd)
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=directory)
        os.close(directory)


def main() -> int:
    parser = SafeParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".env"))
    parser.add_argument("--username", default="baobab-local-bootstrap")
    parser.add_argument("--environment", choices=("local", "ci"), default="local")
    arguments = parser.parse_args()
    try:
        create_local_env(arguments.output, arguments.username, arguments.environment)
    except (OSError, ValueError):
        # Do not dump a traceback, generated values, or private filesystem paths.
        print("Bootstrap preparation refused: check directory permissions and existing output; nothing is overwritten.", file=sys.stderr)
        return 2
    print("Local bootstrap configuration created with mode 0600; secret values are not printed. No account or administrative grant was provisioned.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
