from flask import Blueprint, request, jsonify
from src.models.user import db, User, UserStatus, UserRole
from src.routes.auth import verify_token
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin access"""
    def decorated_function(*args, **kwargs):
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@admin_bp.route('/admin/users', methods=['GET'])
@require_auth
@require_admin
def get_users():
    """Get all users with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        status = request.args.get('status')
        role = request.args.get('role')
        search = request.args.get('search')
        
        # Build query
        query = User.query
        
        # Apply filters
        if status:
            try:
                status_enum = UserStatus(status)
                query = query.filter(User.status == status_enum)
            except ValueError:
                pass
        
        if role:
            try:
                role_enum = UserRole(role)
                query = query.filter(User.role == role_enum)
            except ValueError:
                pass
        
        if search:
            query = query.filter(
                User.first_name.contains(search) |
                User.last_name.contains(search) |
                User.email.contains(search) |
                User.organization_name.contains(search)
            )
        
        # Order by creation date (newest first)
        query = query.order_by(User.created_at.desc())
        
        # Paginate
        users = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict() for user in users.items],
            'pagination': {
                'page': users.page,
                'pages': users.pages,
                'per_page': users.per_page,
                'total': users.total,
                'has_next': users.has_next,
                'has_prev': users.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/pending', methods=['GET'])
@require_auth
@require_admin
def get_pending_users():
    """Get users pending approval"""
    try:
        pending_users = User.query.filter(User.status == UserStatus.PENDING).order_by(User.created_at.desc()).all()
        
        users_data = []
        for user in pending_users:
            user_dict = user.to_dict()
            # Add additional context for approval decisions
            user_dict['days_pending'] = (datetime.utcnow() - user.created_at).days
            users_data.append(user_dict)
        
        return jsonify({
            'pending_users': users_data,
            'count': len(users_data)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>/approve', methods=['POST'])
@require_auth
@require_admin
def approve_user(user_id):
    """Approve pending user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.status != UserStatus.PENDING:
            return jsonify({'error': 'User is not pending approval'}), 400
        
        user.status = UserStatus.ACTIVE
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User approved successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>/reject', methods=['POST'])
@require_auth
@require_admin
def reject_user(user_id):
    """Reject pending user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.status != UserStatus.PENDING:
            return jsonify({'error': 'User is not pending approval'}), 400
        
        data = request.get_json()
        rejection_reason = data.get('reason', 'Application rejected')
        
        user.status = UserStatus.REJECTED
        user.updated_at = datetime.utcnow()
        # Note: In a full implementation, you'd store the rejection reason
        db.session.commit()
        
        return jsonify({
            'message': 'User rejected successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>/suspend', methods=['POST'])
@require_auth
@require_admin
def suspend_user(user_id):
    """Suspend active user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'User is not active'}), 400
        
        data = request.get_json()
        suspension_reason = data.get('reason', 'Account suspended')
        
        user.status = UserStatus.SUSPENDED
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User suspended successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>/reactivate', methods=['POST'])
@require_auth
@require_admin
def reactivate_user(user_id):
    """Reactivate suspended user"""
    try:
        user = User.query.get_or_404(user_id)
        
        if user.status != UserStatus.SUSPENDED:
            return jsonify({'error': 'User is not suspended'}), 400
        
        user.status = UserStatus.ACTIVE
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User reactivated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@require_auth
@require_admin
def update_user(user_id):
    """Update user information (admin only)"""
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        
        # Update allowed fields
        updatable_fields = [
            'first_name', 'last_name', 'phone', 'organization_name',
            'position', 'department', 'address_line1', 'address_line2',
            'city', 'state', 'postcode', 'country', 'bio', 'website',
            'linkedin', 'email_notifications', 'sms_notifications'
        ]
        
        for field in updatable_fields:
            if field in data:
                setattr(user, field, data[field])
        
        # Handle role changes (system admin only)
        if 'role' in data and request.current_user.role == UserRole.SYSTEM_ADMIN:
            try:
                new_role = UserRole(data['role'])
                user.role = new_role
            except ValueError:
                return jsonify({'error': 'Invalid role'}), 400
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/stats', methods=['GET'])
@require_auth
@require_admin
def get_admin_stats():
    """Get admin dashboard statistics"""
    try:
        # User statistics
        total_users = User.query.count()
        pending_users = User.query.filter(User.status == UserStatus.PENDING).count()
        active_users = User.query.filter(User.status == UserStatus.ACTIVE).count()
        
        # Role breakdown
        role_stats = db.session.query(
            User.role,
            db.func.count(User.id)
        ).group_by(User.role).all()
        
        role_breakdown = {role.value: count for role, count in role_stats}
        
        # Recent registrations (last 30 days)
        from datetime import timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_registrations = User.query.filter(
            User.created_at >= thirty_days_ago
        ).count()
        
        return jsonify({
            'total_users': total_users,
            'pending_users': pending_users,
            'active_users': active_users,
            'role_breakdown': role_breakdown,
            'recent_registrations': recent_registrations
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@admin_bp.route('/admin/users/<int:user_id>', methods=['GET'])
@require_auth
@require_admin
def get_user_details(user_id):
    """Get detailed user information"""
    try:
        user = User.query.get_or_404(user_id)
        
        user_data = user.to_dict(include_sensitive=True)
        
        # Add application statistics
        from src.models.application import Application
        user_applications = Application.query.filter(Application.applicant_id == user_id).all()
        
        user_data['application_stats'] = {
            'total_applications': len(user_applications),
            'submitted': len([app for app in user_applications if app.status.value == 'submitted']),
            'approved': len([app for app in user_applications if app.status.value == 'approved']),
            'rejected': len([app for app in user_applications if app.status.value == 'rejected'])
        }
        
        return jsonify(user_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

