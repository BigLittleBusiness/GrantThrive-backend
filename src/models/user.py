from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum
import logging

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

# ── Argon2id hasher — OWASP 2024 recommended parameters ──────────────────────
_hasher = PasswordHasher(
    time_cost=3,        # iterations
    memory_cost=65536,  # 64 MB in KiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

db = SQLAlchemy()

class UserRole(enum.Enum):
    COMMUNITY_MEMBER = "community_member"
    PROFESSIONAL_CONSULTANT = "professional_consultant"
    COUNCIL_STAFF = "council_staff"
    COUNCIL_ADMIN = "council_admin"
    SYSTEM_ADMIN = "system_admin"

class UserStatus(enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REJECTED = "rejected"

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Basic information
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # Personal details
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    
    # Organization details
    organization_name = db.Column(db.String(200), nullable=True)
    position = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    
    # Address
    address_line1 = db.Column(db.String(200), nullable=True)
    address_line2 = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(50), nullable=True)
    postcode = db.Column(db.String(10), nullable=True)
    country = db.Column(db.String(50), nullable=True, default='Australia')
    
    # Role and status
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.COMMUNITY_MEMBER)
    status = db.Column(db.Enum(UserStatus), nullable=False, default=UserStatus.PENDING)
    
    # Timestamps
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Verification
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    email_verification_token = db.Column(db.String(100), nullable=True)
    
    # Profile
    bio = db.Column(db.Text, nullable=True)
    website = db.Column(db.String(200), nullable=True)
    linkedin = db.Column(db.String(200), nullable=True)
    
    # Multi-tenancy subdomain (council admins only)
    # e.g. 'brisbane' for brisbane.grantthrive.com.au
    subdomain = db.Column(db.String(100), nullable=True, unique=True, index=True)

    # Preferences
    email_notifications = db.Column(db.Boolean, nullable=False, default=True)
    sms_notifications = db.Column(db.Boolean, nullable=False, default=False)
    
    def set_password(self, password: str) -> None:
        """Hash password using Argon2id and store the encoded hash."""
        self.password_hash = _hasher.hash(password)

    def check_password(self, password: str):
        """
        Verify a password against the stored hash.

        Returns a tuple (is_valid: bool, needs_rehash: bool).

        For legacy Werkzeug PBKDF2/scrypt hashes (pbkdf2:sha256:... or
        scrypt:...) the hash is verified using Werkzeug, and needs_rehash
        is set to True on success so the caller can transparently upgrade
        the stored hash to Argon2id on the next successful login.

        Callers that only check truthiness of the return value will still
        work correctly because a non-empty tuple is truthy.
        """
        stored = self.password_hash or ''

        # ── Legacy Werkzeug PBKDF2 / scrypt hashes ───────────────────────────
        if stored.startswith('pbkdf2:') or stored.startswith('scrypt:'):
            from werkzeug.security import check_password_hash as _wz_check
            try:
                is_valid = _wz_check(stored, password)
                return is_valid, is_valid  # needs_rehash=True when valid
            except Exception as exc:
                logger.warning('Legacy hash verification error: %s', exc)
                return False, False

        # ── Argon2id ──────────────────────────────────────────────────────────
        try:
            _hasher.verify(stored, password)
            needs_rehash = _hasher.check_needs_rehash(stored)
            return True, needs_rehash
        except VerifyMismatchError:
            return False, False
        except (VerificationError, InvalidHashError) as exc:
            logger.warning('Argon2 verification error: %s', exc)
            return False, False

    @property
    def full_name(self):
        """Get full name"""
        return f"{self.first_name} {self.last_name}"
    
    @property
    def is_government_user(self):
        """Check if user has government email"""
        return (self.email.lower().endswith('.gov.au') or 
                self.email.lower().endswith('.govt.nz'))
    
    @property
    def is_admin(self):
        """Check if user is admin"""
        return self.role in [UserRole.COUNCIL_ADMIN, UserRole.SYSTEM_ADMIN]
    
    @property
    def is_council_staff(self):
        """Check if user is council staff"""
        return self.role in [UserRole.COUNCIL_STAFF, UserRole.COUNCIL_ADMIN]
    
    def to_dict(self, include_sensitive=False):
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.full_name,
            'phone': self.phone,
            'organization_name': self.organization_name,
            'position': self.position,
            'department': self.department,
            'address_line1': self.address_line1,
            'address_line2': self.address_line2,
            'city': self.city,
            'state': self.state,
            'postcode': self.postcode,
            'country': self.country,
            'role': self.role.value if self.role else None,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'email_verified': self.email_verified,
            'bio': self.bio,
            'website': self.website,
            'linkedin': self.linkedin,
            'email_notifications': self.email_notifications,
            'sms_notifications': self.sms_notifications,
            'is_government_user': self.is_government_user,
            'is_admin': self.is_admin,
            'is_council_staff': self.is_council_staff,
            'subdomain': self.subdomain
        }
        
        if include_sensitive:
            data['email_verification_token'] = self.email_verification_token
        
        return data
    
    def __repr__(self):
        return f'<User {self.email}>'
