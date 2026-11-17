"""Admin CLI.  Usage (inside the container):

    python -m app.cli set-password [username]   # prompts securely, no echo; revokes sessions
    python -m app.cli gen-secret-key            # print a new key for EOS_SECRET_KEY
    python -m app.cli rotate-secrets            # re-encrypt stored credentials with the first key
    python -m app.cli revoke-all                # incident response: kill all sessions + API tokens
"""

from __future__ import annotations

import getpass
import sys

from app.config import get_settings
from app.db import get_db, init_db, now
from app.security import hash_password, password_problem


def set_password(username: str) -> int:
    password = getpass.getpass(f"New password for '{username}': ")
    problem = password_problem(password, username)
    if problem:
        print(f"{problem}.", file=sys.stderr)
        return 1
    if getpass.getpass("Repeat: ") != password:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    init_db(get_settings().db_path)
    with get_db() as db:
        row = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(password), row["id"]))
            db.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
        else:
            db.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, hash_password(password), now()),
            )
    print("Password updated; existing sessions revoked.")
    return 0


def gen_secret_key() -> int:
    from cryptography.fernet import Fernet

    print(Fernet.generate_key().decode("ascii"))
    return 0


def rotate_secrets() -> int:
    from app import secretbox

    init_db(get_settings().db_path)
    try:
        with get_db() as db:
            changed = secretbox.migrate_and_rotate(db, rotate_all=True)
    except secretbox.SecretError as exc:
        print(f"Rotation aborted, nothing changed: {exc}", file=sys.stderr)
        return 1
    print(f"Re-encrypted {changed} stored credential(s) with the primary key. "
          "You can now remove old keys from EOS_SECRET_KEY.")
    return 0


def revoke_all() -> int:
    init_db(get_settings().db_path)
    with get_db() as db:
        sessions = db.execute("DELETE FROM sessions").rowcount
        tokens = db.execute("DELETE FROM api_tokens").rowcount
    print(f"Revoked {sessions} session(s) and {tokens} API token(s).")
    return 0



COMMANDS = {
    "gen-secret-key": gen_secret_key,
    "rotate-secrets": rotate_secrets,
    "revoke-all": revoke_all,
}


def main(argv: list[str]) -> int:
    if len(argv) >= 1 and argv[0] == "set-password":
        return set_password(argv[1] if len(argv) > 1 else get_settings().admin_user)
    if len(argv) == 1 and argv[0] in COMMANDS:
        return COMMANDS[argv[0]]()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
