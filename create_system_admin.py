#!/usr/bin/env python3
"""
GrantThrive — Create System Admin Account
==========================================
Use this script to create SYSTEM_ADMIN accounts directly in the database.
This is the only supported method for creating system administrators, as
there is no public-facing registration path for this role by design.

Usage:
    python3 create_system_admin.py

The script will prompt for the admin's details interactively.
Passwords are entered securely (not echoed to the terminal).

Requirements:
    Run from the root of the grantthrive-backend directory.
    The database must already exist (run setup.sh first if it does not).
"""

import os
import sys
import getpass
import re

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask
from src.models.user import db, User, UserRole, UserStatus
from argon2 import PasswordHasher as _PasswordHasher
from datetime import datetime

# Argon2id hasher — OWASP 2024 recommended parameters (matches src/models/user.py)
_hasher = _PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def create_app():
    app = Flask(__name__)
    db_path = os.path.join(os.path.dirname(__file__), 'src', 'database', 'app.db')
    db_uri = os.environ.get('DATABASE_URL', f'sqlite:///{db_path}')
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app


def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_password(password):
    if len(password) < 10:
        return False, "Password must be at least 10 characters."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "OK"


def main():
    print("=" * 55)
    print("  GrantThrive — Create System Admin Account")
    print("=" * 55)
    print()

    app = create_app()

    with app.app_context():
        db.create_all()

        # Collect details
        print("Enter the details for the new System Admin account.\n")

        first_name = input("First name: ").strip()
        if not first_name:
            print("ERROR: First name is required.")
            sys.exit(1)

        last_name = input("Last name: ").strip()
        if not last_name:
            print("ERROR: Last name is required.")
            sys.exit(1)

        email = input("Email address: ").strip().lower()
        if not validate_email(email):
            print("ERROR: Invalid email address format.")
            sys.exit(1)

        # Check for duplicate
        existing = User.query.filter_by(email=email).first()
        if existing:
            print(f"ERROR: A user with the email '{email}' already exists (role: {existing.role.value}, status: {existing.status.value}).")
            sys.exit(1)

        # Password
        while True:
            password = getpass.getpass("Password (min 10 chars, upper, lower, number, special): ")
            valid, msg = validate_password(password)
            if not valid:
                print(f"ERROR: {msg}")
                continue
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("ERROR: Passwords do not match. Please try again.")
                continue
            break

        # Confirm before creating
        print()
        print("Summary:")
        print(f"  Name  : {first_name} {last_name}")
        print(f"  Email : {email}")
        print(f"  Role  : SYSTEM_ADMIN")
        print(f"  Status: ACTIVE")
        print()
        confirm_create = input("Create this System Admin account? (yes/no): ").strip().lower()
        if confirm_create != 'yes':
            print("Aborted. No account was created.")
            sys.exit(0)

        # Create the user — password hashed with Argon2id (OWASP 2024)
        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=_hasher.hash(password),
            role=UserRole.SYSTEM_ADMIN,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        db.session.add(user)
        db.session.commit()

        print()
        print(f"SUCCESS: System Admin account created for {first_name} {last_name} ({email}).")
        print("They can now log in at the /admin path using these credentials.")
        print()


if __name__ == '__main__':
    main()
