from flask import Blueprint, request, jsonify, current_app
from werkzeug.security import generate_password_hash
from src.models.user import db, User, UserRole, UserStatus
import jwt
from datetime import datetime, timedelta
import re

auth_bp = Blueprint('auth', __name__)

def validate_government_email(email):
    """Validate government email domains"""
    email_lower = email.lower()
    australian_gov_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.gov\.au$'
    new_zealand_gov_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.govt\.nz$'
    
    return (re.match(australian_gov_pattern, email_lower) or 
            re.match(new_zealand_gov_pattern, email_lower))

def generate_token(user_id):
    """Generate JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@auth_bp.route('/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'password', 'first_name', 'last_name', 'user_type']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Validate user type and email domain
        user_type = data['user_type']
        email = data['email']
        
        if user_type == 'council_staff':
            if not validate_government_email(email):
                return jsonify({
                    'error': 'Council staff must use government email (.gov.au or .govt.nz)'
                }), 400
            role = UserRole.COUNCIL_STAFF
            status = UserStatus.PENDING  # Requires admin approval
        elif user_type == 'professional_consultant':
            role = UserRole.PROFESSIONAL_CONSULTANT
            status = UserStatus.PENDING  # Requires verification
        else:
            role = UserRole.COMMUNITY_MEMBER
            status = UserStatus.ACTIVE  # Immediate approval
        
        # Create new user
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
            email_verified=False
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        # Generate token for active users
        token = None
        if status == UserStatus.ACTIVE:
            token = generate_token(user.id)
        
        return jsonify({
            'message': 'Registration successful',
            'user': user.to_dict(),
            'token': token,
            'requires_approval': status == UserStatus.PENDING
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        if user.status != UserStatus.ACTIVE:
            status_messages = {
                UserStatus.PENDING: 'Account pending approval',
                UserStatus.SUSPENDED: 'Account suspended',
                UserStatus.REJECTED: 'Account rejected'
            }
            return jsonify({
                'error': status_messages.get(user.status, 'Account not active')
            }), 403
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        # Generate token
        token = generate_token(user.id)
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'token': token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/verify-token', methods=['POST'])
def verify_user_token():
    """Verify JWT token endpoint"""
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

@auth_bp.route('/demo-login', methods=['POST'])
def demo_login():
    """Demo login for testing purposes"""
    try:
        data = request.get_json()
        demo_type = data.get('demo_type', 'community_member')
        
        # Create or get demo users
        demo_users = {
            'council_admin': {
                'email': 'sarah.johnson@melbourne.vic.gov.au',
                'first_name': 'Sarah',
                'last_name': 'Johnson',
                'role': UserRole.COUNCIL_ADMIN,
                'organization_name': 'Melbourne City Council',
                'position': 'Grants Manager',
                'department': 'Community Development'
            },
            'council_staff': {
                'email': 'michael.chen@melbourne.vic.gov.au',
                'first_name': 'Michael',
                'last_name': 'Chen',
                'role': UserRole.COUNCIL_STAFF,
                'organization_name': 'Melbourne City Council',
                'position': 'Grants Officer',
                'department': 'Community Development'
            },
            'community_member': {
                'email': 'emma.thompson@communityarts.org.au',
                'first_name': 'Emma',
                'last_name': 'Thompson',
                'role': UserRole.COMMUNITY_MEMBER,
                'organization_name': 'Community Arts Collective',
                'position': 'Director',
                'department': None
            },
            'professional_consultant': {
                'email': 'david.wilson@grantsuccess.com.au',
                'first_name': 'David',
                'last_name': 'Wilson',
                'role': UserRole.PROFESSIONAL_CONSULTANT,
                'organization_name': 'Grant Success Consulting',
                'position': 'Senior Consultant',
                'department': None
            }
        }
        
        if demo_type not in demo_users:
            return jsonify({'error': 'Invalid demo type'}), 400
        
        demo_data = demo_users[demo_type]
        
        # Check if demo user exists
        user = User.query.filter_by(email=demo_data['email']).first()
        
        if not user:
            # Create demo user
            user = User(
                email=demo_data['email'],
                first_name=demo_data['first_name'],
                last_name=demo_data['last_name'],
                role=demo_data['role'],
                organization_name=demo_data['organization_name'],
                position=demo_data['position'],
                department=demo_data['department'],
                status=UserStatus.ACTIVE,
                email_verified=True
            )
            user.set_password('demo123')
            db.session.add(user)
            db.session.commit()
        
        # Generate token
        token = generate_token(user.id)
        
        return jsonify({
            'message': 'Demo login successful',
            'user': user.to_dict(),
            'token': token
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    # In a JWT system, logout is typically handled client-side
    # by removing the token from storage
    return jsonify({'message': 'Logout successful'}), 200

