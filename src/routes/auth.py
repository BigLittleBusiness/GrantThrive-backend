from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash
from src.models.user import db, User, UserRole, UserStatus
from src.utils.email import email_service
import jwt
import re
import os
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_government_email(email):
    """Validate government email domains (.gov.au or .govt.nz)"""
    email_lower = email.lower()
    au_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.gov\.au$'
    nz_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.govt\.nz$'
    return bool(re.match(au_pattern, email_lower) or re.match(nz_pattern, email_lower))


def extract_email_domain(email):
    """Return the full domain portion of an email address (lowercased)."""
    return email.lower().split('@')[1]


def derive_default_subdomain(email, organization_name=None):
    """
    Derive a URL-safe subdomain suggestion from the council's email domain
    or organisation name.

    Examples:
      brisbane.qld.gov.au  -> brisbane
      cityofmelbourne.vic.gov.au -> cityofmelbourne
      'Brisbane City Council' -> brisbane-city-council
    """
    if organization_name:
        slug = re.sub(r'[^a-z0-9]+', '-', organization_name.lower()).strip('-')
        return slug[:50]
    # Fall back to the first label of the domain
    domain = extract_email_domain(email)
    first_label = domain.split('.')[0]
    return re.sub(r'[^a-z0-9-]', '', first_label)[:50]


def generate_token(user_id):
    """Generate a signed JWT token valid for 7 days."""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')


def verify_token(token):
    """Decode a JWT token and return the user_id, or None if invalid/expired."""
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    ---
    tags:
      - Auth
    security: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [email, password, first_name, last_name, user_type]
          properties:
            email:
              type: string
              example: jane.doe@brisbane.qld.gov.au
            password:
              type: string
              example: SecurePass123!
            first_name:
              type: string
              example: Jane
            last_name:
              type: string
              example: Doe
            user_type:
              type: string
              enum: [community_member, council]
              example: council
            organization_name:
              type: string
              example: Brisbane City Council
            position:
              type: string
              example: Grants Manager
            phone:
              type: string
              example: "+61 7 3403 8888"
            subdomain:
              type: string
              description: Preferred subdomain (e.g. 'brisbane' -> brisbane.grantthrive.com.au)
              example: brisbane
    responses:
      201:
        description: Registration successful
      400:
        description: Validation error or missing fields
      409:
        description: Council domain already registered
      500:
        description: Server error
    """
    try:
        data = request.get_json()

        # --- Required field validation ---
        required_fields = ['email', 'password', 'first_name', 'last_name', 'user_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        # --- Password complexity validation (server-side safety net) ---
        password = data['password']
        pw_errors = []
        if len(password) < 10:
            pw_errors.append('at least 10 characters')
        if not re.search(r'[A-Z]', password):
            pw_errors.append('one uppercase letter (A–Z)')
        if not re.search(r'[a-z]', password):
            pw_errors.append('one lowercase letter (a–z)')
        if not re.search(r'[0-9]', password):
            pw_errors.append('one number (0–9)')
        if not re.search(r'[^A-Za-z0-9]', password):
            pw_errors.append('one special character (!@#$%…)')
        if pw_errors:
            return jsonify({
                'error': 'Password does not meet requirements. Missing: ' + ', '.join(pw_errors) + '.'
            }), 400

        email = data['email'].strip().lower()
        user_type = data['user_type']

        # --- Duplicate email check ---
        if User.query.filter_by(email=email).first():
            return jsonify({'error': 'Email already registered'}), 400

        # --- Route by user_type ---
        if user_type == 'council':
            # Council registrations must use a government email
            if not validate_government_email(email):
                return jsonify({
                    'error': 'Council accounts must use a government email address '
                             '(.gov.au or .govt.nz)'
                }), 400

            domain = extract_email_domain(email)

            # Check whether another user from this domain already exists
            existing_domain_user = User.query.filter(
                User.email.ilike(f'%@{domain}')
            ).first()

            if existing_domain_user:
                return jsonify({
                    'error': (
                        'Your council is already registered on GrantThrive. '
                        'Please contact your Council Administrator to be added '
                        'as a staff member.'
                    )
                }), 409

            # First registrant from this domain → Council Admin
            role = UserRole.COUNCIL_ADMIN
            status = UserStatus.PENDING  # Requires System Admin approval

            # Subdomain: use the value supplied by the user, or derive a default
            requested_subdomain = data.get('subdomain', '').strip().lower()
            if not requested_subdomain:
                requested_subdomain = derive_default_subdomain(
                    email, data.get('organization_name')
                )

            # Sanitise: only lowercase letters, digits, hyphens
            requested_subdomain = re.sub(r'[^a-z0-9-]', '', requested_subdomain)[:50]

            # Ensure subdomain is unique
            if User.query.filter_by(subdomain=requested_subdomain).first():
                # Append a numeric suffix to make it unique
                suffix = 1
                while User.query.filter_by(
                    subdomain=f'{requested_subdomain}-{suffix}'
                ).first():
                    suffix += 1
                requested_subdomain = f'{requested_subdomain}-{suffix}'

        elif user_type == 'community_member':
            role = UserRole.COMMUNITY_MEMBER
            status = UserStatus.ACTIVE   # Immediate activation
            requested_subdomain = None

        else:
            return jsonify({
                'error': (
                    f"Invalid user_type '{user_type}'. "
                    "Accepted values: 'community_member', 'council'."
                )
            }), 400

        # --- Create user ---
        user = User(
            email=email,
            first_name=data['first_name'],
            last_name=data['last_name'],
            phone=data.get('phone'),
            organization_name=data.get('organization_name'),
            position=data.get('position'),
            department=data.get('department'),
            role=role,
            status=status,
            subdomain=requested_subdomain if user_type == 'council' else None,
            email_verified=False
        )
        user.set_password(data['password'])

        db.session.add(user)
        db.session.commit()

        # --- Post-registration emails ---
        if status == UserStatus.ACTIVE:
            # Community member: send welcome email immediately
            try:
                email_service.send_welcome_email(
                    user_email=user.email,
                    user_name=user.full_name,
                    user_role=user.role.value
                )
            except Exception as email_err:
                current_app.logger.warning(
                    f'Welcome email failed for {user.email}: {email_err}'
                )

        elif status == UserStatus.PENDING and role == UserRole.COUNCIL_ADMIN:
            # Notify all System Admins that a new council is awaiting approval
            try:
                system_admins = User.query.filter_by(
                    role=UserRole.SYSTEM_ADMIN,
                    status=UserStatus.ACTIVE
                ).all()
                admin_email = os.getenv('SYSTEM_ADMIN_EMAIL', '')
                notify_emails = [u.email for u in system_admins]
                if admin_email and admin_email not in notify_emails:
                    notify_emails.append(admin_email)
                for admin_addr in notify_emails:
                    email_service.send_admin_approval_notification(
                        admin_email=admin_addr,
                        user_name=user.full_name,
                        user_email=user.email,
                        user_role=user.role.value
                    )
            except Exception as email_err:
                current_app.logger.warning(
                    f'Admin approval notification failed: {email_err}'
                )

        # Generate token only for immediately active users
        token = generate_token(user.id) if status == UserStatus.ACTIVE else None

        return jsonify({
            'message': 'Registration successful',
            'user': user.to_dict(),
            'token': token,
            'requires_approval': status == UserStatus.PENDING,
            'subdomain': requested_subdomain
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login and receive a JWT bearer token
    ---
    tags:
      - Auth
    security: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [email, password]
          properties:
            email:
              type: string
              example: jane.doe@brisbane.qld.gov.au
            password:
              type: string
              example: SecurePass123!
    responses:
      200:
        description: Login successful - returns user and JWT token
      401:
        description: Invalid credentials
      403:
        description: Account pending, suspended, or rejected
      500:
        description: Server error
    """
    try:
        data = request.get_json()

        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=data['email'].strip().lower()).first()

        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401

        if user.status != UserStatus.ACTIVE:
            status_messages = {
                UserStatus.PENDING: 'Your account is pending approval. You will receive an email once approved.',
                UserStatus.SUSPENDED: 'Account suspended. Please contact support.',
                UserStatus.REJECTED: 'Account application was not approved.'
            }
            return jsonify({
                'error': status_messages.get(user.status, 'Account not active')
            }), 403

        user.last_login = datetime.utcnow()
        db.session.commit()

        token = generate_token(user.id)

        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'token': token
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------

@auth_bp.route('/verify-token', methods=['POST'])
def verify_user_token():
    """
    Verify a JWT token and return the associated user
    ---
    tags:
      - Auth
    security: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [token]
          properties:
            token:
              type: string
              example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    responses:
      200:
        description: Token is valid
      401:
        description: Invalid or expired token
    """
    try:
        data = request.get_json()
        token = data.get('token')

        if not token:
            return jsonify({'error': 'Token is required'}), 400

        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401

        user = User.query.get(user_id)
        if not user or user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'User not found or inactive'}), 401

        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Demo login (development / testing only)
# ---------------------------------------------------------------------------

@auth_bp.route('/demo-login', methods=['POST'])
def demo_login():
    """
    Demo login for development and testing
    ---
    tags:
      - Auth
    security: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            demo_type:
              type: string
              enum: [council_admin, council_staff, community_member, professional_consultant]
              example: council_admin
    responses:
      200:
        description: Demo login successful
      400:
        description: Invalid demo type
    """
    try:
        data = request.get_json()
        demo_type = data.get('demo_type', 'community_member')

        demo_users = {
            'council_admin': {
                'email': 'sarah.johnson@melbourne.vic.gov.au',
                'first_name': 'Sarah',
                'last_name': 'Johnson',
                'role': UserRole.COUNCIL_ADMIN,
                'organization_name': 'Melbourne City Council',
                'position': 'Grants Manager',
                'department': 'Community Development',
                'subdomain': 'melbourne'
            },
            'council_staff': {
                'email': 'michael.chen@melbourne.vic.gov.au',
                'first_name': 'Michael',
                'last_name': 'Chen',
                'role': UserRole.COUNCIL_STAFF,
                'organization_name': 'Melbourne City Council',
                'position': 'Grants Officer',
                'department': 'Community Development',
                'subdomain': None
            },
            'community_member': {
                'email': 'emma.thompson@communityarts.org.au',
                'first_name': 'Emma',
                'last_name': 'Thompson',
                'role': UserRole.COMMUNITY_MEMBER,
                'organization_name': 'Community Arts Collective',
                'position': 'Director',
                'department': None,
                'subdomain': None
            },
            'professional_consultant': {
                'email': 'david.wilson@grantsuccess.com.au',
                'first_name': 'David',
                'last_name': 'Wilson',
                'role': UserRole.PROFESSIONAL_CONSULTANT,
                'organization_name': 'Grant Success Consulting',
                'position': 'Senior Consultant',
                'department': None,
                'subdomain': None
            }
        }

        if demo_type not in demo_users:
            return jsonify({'error': 'Invalid demo type'}), 400

        demo_data = demo_users[demo_type]
        user = User.query.filter_by(email=demo_data['email']).first()

        if not user:
            user = User(
                email=demo_data['email'],
                first_name=demo_data['first_name'],
                last_name=demo_data['last_name'],
                role=demo_data['role'],
                organization_name=demo_data['organization_name'],
                position=demo_data['position'],
                department=demo_data['department'],
                subdomain=demo_data.get('subdomain'),
                status=UserStatus.ACTIVE,
                email_verified=True
            )
            user.set_password('demo123')
            db.session.add(user)
            db.session.commit()

        token = generate_token(user.id)

        return jsonify({
            'message': 'Demo login successful',
            'user': user.to_dict(),
            'token': token
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """
    Logout (stateless - client discards the token)
    ---
    tags:
      - Auth
    responses:
      200:
        description: Logout acknowledged
    """
    return jsonify({'message': 'Logout successful'}), 200
