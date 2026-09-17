#!/usr/bin/env python3
"""
Sudarshan :: Auth (auth.py)
Phase 6 of the Sudarshan web frontend - bcrypt + JWT authentication
helpers, plus a CLI for managing user accounts.

Account creation/deletion is deliberately CLI-only (no web route does
this) - per Frontend flow.txt and SUDARSHAN_ROADMAP_PHASE5_TO_LAUNCH.md's
Phase 6 scope, this keeps account provisioning off the public attack
surface entirely.

USAGE (CLI)
-----------
  python3 auth.py --add-user alice
  python3 auth.py --change-password alice
  python3 auth.py --del-user alice
  python3 auth.py --list-users

REQUIREMENTS
------------
  pip install bcrypt pyjwt

ENVIRONMENT
-----------
  SUDARSHAN_JWT_SECRET   Required. Signs/verifies JWT session cookies.
                          Generate one with:
                            python3 -c "import secrets; print(secrets.token_hex(32))"
                          Put it in .env - never hardcode it, never commit it.
                          (Same pattern as NVD_API_KEY - see sudarshan_config.py.)
  SUDARSHAN_USERS_FILE   Optional. Path to the credentials JSON file.
                          Default: users.json next to this file. This file
                          must be in .gitignore - it holds bcrypt hashes,
                          never plaintext, but still should never be committed.
"""

import argparse
import datetime
import getpass
import json
import os
import sys

try:
    import bcrypt
except ImportError:
    bcrypt = None

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None


USERS_FILE = os.environ.get(
    "SUDARSHAN_USERS_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json"),
)

JWT_ALGO = "HS256"
JWT_EXPIRY_HOURS = 12
MIN_PASSWORD_LEN = 8


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def _require_bcrypt():
    if bcrypt is None:
        raise RuntimeError("'bcrypt' not installed. Install with: pip install bcrypt")


def _require_jwt():
    if pyjwt is None:
        raise RuntimeError("'pyjwt' not installed. Install with: pip install pyjwt")


def get_jwt_secret():
    secret = os.environ.get("SUDARSHAN_JWT_SECRET")
    if not secret:
        raise RuntimeError(
            "SUDARSHAN_JWT_SECRET is not set. Generate one with:\n"
            "  python3 -c \"import secrets; print(secrets.token_hex(32))\"\n"
            "and add it to your .env file (never hardcode it, never commit it)."
        )
    return secret


# ----------------------------------------------------------------------------
# users.json storage
# ----------------------------------------------------------------------------


def load_users():
    if not os.path.isfile(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_users(users):
    os.makedirs(os.path.dirname(os.path.abspath(USERS_FILE)) or ".", exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    try:
        # Best-effort - restrict to owner-read/write. Not fatal if the
        # filesystem doesn't support it (e.g. some mounted volumes).
        os.chmod(USERS_FILE, 0o600)
    except OSError:
        pass


def add_user(username, password):
    _require_bcrypt()
    username = username.strip()
    if not username:
        raise ValueError("Username cannot be empty.")
    if len(password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    users = load_users()
    if username in users:
        raise ValueError(f"User '{username}' already exists. Use --change-password to update it.")
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[username] = {
        "password_hash": pw_hash,
        "created_at": datetime.datetime.now().isoformat(),
    }
    save_users(users)


def change_password(username, new_password):
    _require_bcrypt()
    if len(new_password) < MIN_PASSWORD_LEN:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    users = load_users()
    if username not in users:
        raise ValueError(f"No such user: '{username}'")
    pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    users[username]["password_hash"] = pw_hash
    users[username]["password_changed_at"] = datetime.datetime.now().isoformat()
    save_users(users)


def delete_user(username):
    users = load_users()
    if username not in users:
        raise ValueError(f"No such user: '{username}'")
    del users[username]
    save_users(users)


def list_users():
    return sorted(load_users().keys())


def verify_password(username, password):
    """Returns True/False. Raises RuntimeError only for missing deps -
    never for a wrong username/password (that's just False)."""
    _require_bcrypt()
    users = load_users()
    entry = users.get(username)
    if not entry:
        # Still run bcrypt against a dummy hash so a nonexistent username
        # doesn't respond measurably faster than a wrong password for an
        # existing one - avoids leaking which usernames exist via timing.
        bcrypt.checkpw(password.encode("utf-8"), bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return False
    return bcrypt.checkpw(password.encode("utf-8"), entry["password_hash"].encode("utf-8"))


# ----------------------------------------------------------------------------
# JWT session tokens
# ----------------------------------------------------------------------------


def create_token(username, expiry_hours=JWT_EXPIRY_HOURS):
    _require_jwt()
    secret = get_jwt_secret()
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username,
        "iat": now,
        "exp": now + datetime.timedelta(hours=expiry_hours),
    }
    return pyjwt.encode(payload, secret, algorithm=JWT_ALGO)


def verify_token(token):
    """Returns the username if the token is valid and the user still
    exists, else None. Never raises - callers should treat None as 'not
    authenticated' without needing to distinguish why (expired, tampered,
    secret missing, user deleted, etc.)."""
    if not token:
        return None
    try:
        _require_jwt()
        secret = get_jwt_secret()
    except RuntimeError:
        return None
    try:
        payload = pyjwt.decode(token, secret, algorithms=[JWT_ALGO])
    except pyjwt.PyJWTError:
        return None
    username = payload.get("sub")
    # A deleted account's outstanding token stops working immediately,
    # rather than lingering valid until natural expiry.
    if username not in load_users():
        return None
    return username


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Sudarshan Phase 6: manage user accounts. "
                     "CLI-only by design - no web route creates or deletes accounts.",
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--add-user", metavar="USERNAME", help="Create a new user (prompts for password)")
    g.add_argument("--del-user", metavar="USERNAME", help="Delete a user")
    g.add_argument("--change-password", metavar="USERNAME", help="Change a user's password (prompts)")
    g.add_argument("--list-users", action="store_true", help="List all usernames")
    return p


def _prompt_password_pair(label):
    pw1 = getpass.getpass(f"{label}: ")
    pw2 = getpass.getpass("Confirm password: ")
    if pw1 != pw2:
        eprint("[!] Passwords did not match.")
        sys.exit(1)
    return pw1


def main():
    args = build_arg_parser().parse_args()

    if args.list_users:
        users = list_users()
        if not users:
            print("[i] No users yet. Add one with: python3 auth.py --add-user <username>")
        for u in users:
            print(f"  - {u}")
        return

    if args.add_user:
        pw = _prompt_password_pair(f"Password for new user '{args.add_user}'")
        try:
            add_user(args.add_user, pw)
        except (ValueError, RuntimeError) as e:
            eprint(f"[!] {e}")
            sys.exit(1)
        print(f"[+] User '{args.add_user}' created.")
        return

    if args.change_password:
        pw = _prompt_password_pair(f"New password for '{args.change_password}'")
        try:
            change_password(args.change_password, pw)
        except (ValueError, RuntimeError) as e:
            eprint(f"[!] {e}")
            sys.exit(1)
        print(f"[+] Password updated for '{args.change_password}'.")
        return

    if args.del_user:
        try:
            delete_user(args.del_user)
        except ValueError as e:
            eprint(f"[!] {e}")
            sys.exit(1)
        print(f"[+] User '{args.del_user}' deleted. Any outstanding session token for "
              f"them stops working immediately (verify_token rejects unknown users).")
        return


if __name__ == "__main__":
    main()
