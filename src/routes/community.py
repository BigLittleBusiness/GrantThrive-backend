"""
GrantThrive — Community Member API Routes
==========================================
All endpoints under /api/community/ are exclusively for authenticated
COMMUNITY_MEMBER users. Council staff and council admins cannot access
these routes.

Endpoints:
  GET    /api/community/profile              — Get own profile
  PUT    /api/community/profile              — Update own profile
  GET    /api/community/grants               — Browse available grants
  GET    /api/community/grants/<id>          — Get grant details
  GET    /api/community/applications         — List own applications
  GET    /api/community/applications/<id>    — Get application detail
  POST   /api/community/applications         — Submit a new application
  PUT    /api/community/applications/<id>    — Update a draft application
  GET    /api/community/dashboard            — Dashboard metrics for community member
  GET    /api/community/notifications        — Get own notifications
  PATCH  /api/community/notifications/<id>   — Mark notification as read
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from src.models.user import db, User, UserRole, UserStatus
from src.models.grant import Grant, GrantStatus
from src.models.application import Application, ApplicationStatus
import jwt
import os
from datetime import datetime

community_bp = Blueprint('community', __name__)


# ─── Auth decorator ──────────────────────────────────────────────────────────

def require_community(f):
    """Require a valid JWT belonging to a COMMUNITY_MEMBER."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        token = auth_header.split(' ', 1)[1]
        try:
            secret = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')
            payload = jwt.decode(token, secret, algorithms=['HS256'])
            user = User.query.get(payload.get('user_id'))
            if not user or user.status != UserStatus.ACTIVE:
                return jsonify({'error': 'Account not active'}), 403
            if user.role != UserRole.COMMUNITY_MEMBER:
                return jsonify({'error': 'Access restricted to community members'}), 403
            request.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Profile ─────────────────────────────────────────────────────────────────

@community_bp.route('/community/profile', methods=['GET'])
@require_community
def get_community_profile():
    """
    Get community member profile
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    responses:
      200:
        description: Community member profile
    """
    user = request.current_user
    return jsonify({'user': user.to_dict()}), 200


@community_bp.route('/community/profile', methods=['PUT'])
@require_community
def update_community_profile():
    """
    Update community member profile
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            first_name:
              type: string
            last_name:
              type: string
            phone:
              type: string
    responses:
      200:
        description: Profile updated
    """
    user = request.current_user
    data = request.get_json() or {}
    allowed = ['first_name', 'last_name', 'phone', 'address', 'bio']
    for field in allowed:
        if field in data:
            setattr(user, field, data[field])
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Profile updated', 'user': user.to_dict()}), 200


# ─── Grants (read-only for community members) ────────────────────────────────

@community_bp.route('/community/grants', methods=['GET'])
@require_community
def community_get_grants():
    """
    Browse grants available to community members
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: category
        type: string
      - in: query
        name: search
        type: string
      - in: query
        name: page
        type: integer
      - in: query
        name: per_page
        type: integer
    responses:
      200:
        description: List of available grants
    """
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    category = request.args.get('category')
    search = request.args.get('search', '').strip()

    query = Grant.query.filter_by(status=GrantStatus.PUBLISHED)

    if category:
        query = query.filter(Grant.category == category)
    if search:
        query = query.filter(
            Grant.title.ilike(f'%{search}%') |
            Grant.description.ilike(f'%{search}%')
        )

    pagination = query.order_by(Grant.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'grants': [g.to_dict() for g in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200


@community_bp.route('/community/grants/<int:grant_id>', methods=['GET'])
@require_community
def community_get_grant(grant_id):
    """
    Get a single grant's details
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: grant_id
        type: integer
        required: true
    responses:
      200:
        description: Grant details
      404:
        description: Grant not found
    """
    grant = Grant.query.filter_by(id=grant_id, status=GrantStatus.PUBLISHED).first()
    if not grant:
        return jsonify({'error': 'Grant not found'}), 404
    return jsonify({'grant': grant.to_dict()}), 200


# ─── Applications ─────────────────────────────────────────────────────────────

@community_bp.route('/community/applications', methods=['GET'])
@require_community
def community_get_applications():
    """
    List all applications submitted by the current community member
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: status
        type: string
      - in: query
        name: page
        type: integer
    responses:
      200:
        description: List of applications
    """
    user = request.current_user
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status_filter = request.args.get('status')

    query = Application.query.filter_by(applicant_id=user.id)
    if status_filter:
        try:
            query = query.filter_by(status=ApplicationStatus(status_filter))
        except ValueError:
            pass

    pagination = query.order_by(Application.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'applications': [a.to_dict() for a in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200


@community_bp.route('/community/applications/<int:application_id>', methods=['GET'])
@require_community
def community_get_application(application_id):
    """
    Get a single application belonging to the current community member
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: application_id
        type: integer
        required: true
    responses:
      200:
        description: Application detail
      403:
        description: Not your application
      404:
        description: Application not found
    """
    user = request.current_user
    application = Application.query.get(application_id)
    if not application:
        return jsonify({'error': 'Application not found'}), 404
    if application.applicant_id != user.id:
        return jsonify({'error': 'Access denied'}), 403
    return jsonify({'application': application.to_dict()}), 200


@community_bp.route('/community/applications', methods=['POST'])
@require_community
def community_create_application():
    """
    Submit a new grant application
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - grant_id
            - project_title
            - project_description
            - amount_requested
          properties:
            grant_id:
              type: integer
            project_title:
              type: string
            project_description:
              type: string
            amount_requested:
              type: number
    responses:
      201:
        description: Application created
      400:
        description: Validation error
      404:
        description: Grant not found or not accepting applications
    """
    user = request.current_user
    data = request.get_json() or {}

    grant_id = data.get('grant_id')
    if not grant_id:
        return jsonify({'error': 'grant_id is required'}), 400

    grant = Grant.query.filter_by(id=grant_id, status=GrantStatus.PUBLISHED).first()
    if not grant:
        return jsonify({'error': 'Grant not found or not currently accepting applications'}), 404

    # Check for duplicate application
    existing = Application.query.filter_by(
        grant_id=grant_id, applicant_id=user.id
    ).filter(
        Application.status != ApplicationStatus.WITHDRAWN
    ).first()
    if existing:
        return jsonify({'error': 'You have already applied for this grant'}), 409

    application = Application(
        grant_id=grant_id,
        applicant_id=user.id,
        project_title=data.get('project_title', ''),
        project_description=data.get('project_description', ''),
        amount_requested=data.get('amount_requested', 0),
        status=ApplicationStatus.DRAFT,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(application)
    db.session.commit()

    return jsonify({
        'message': 'Application created successfully',
        'application': application.to_dict()
    }), 201


@community_bp.route('/community/applications/<int:application_id>', methods=['PUT'])
@require_community
def community_update_application(application_id):
    """
    Update a draft application
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: application_id
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
    responses:
      200:
        description: Application updated
      403:
        description: Not your application or not in draft status
      404:
        description: Application not found
    """
    user = request.current_user
    application = Application.query.get(application_id)
    if not application:
        return jsonify({'error': 'Application not found'}), 404
    if application.applicant_id != user.id:
        return jsonify({'error': 'Access denied'}), 403
    if application.status != ApplicationStatus.DRAFT:
        return jsonify({'error': 'Only draft applications can be edited'}), 403

    data = request.get_json() or {}
    allowed = ['project_title', 'project_description', 'amount_requested',
               'supporting_documents', 'answers']
    for field in allowed:
        if field in data:
            setattr(application, field, data[field])
    application.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Application updated',
        'application': application.to_dict()
    }), 200


# ─── Dashboard ────────────────────────────────────────────────────────────────

@community_bp.route('/community/dashboard', methods=['GET'])
@require_community
def community_dashboard():
    """
    Get dashboard metrics for the current community member
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    responses:
      200:
        description: Dashboard metrics
    """
    user = request.current_user

    total_applications = Application.query.filter_by(applicant_id=user.id).count()
    approved = Application.query.filter_by(
        applicant_id=user.id, status=ApplicationStatus.APPROVED
    ).count()
    pending = Application.query.filter_by(
        applicant_id=user.id, status=ApplicationStatus.SUBMITTED
    ).count()
    draft = Application.query.filter_by(
        applicant_id=user.id, status=ApplicationStatus.DRAFT
    ).count()
    available_grants = Grant.query.filter_by(status=GrantStatus.PUBLISHED).count()

    return jsonify({
        'metrics': {
            'total_applications': total_applications,
            'approved': approved,
            'pending_review': pending,
            'drafts': draft,
            'available_grants': available_grants
        }
    }), 200


# ─── Notifications ────────────────────────────────────────────────────────────

@community_bp.route('/community/notifications', methods=['GET'])
@require_community
def community_get_notifications():
    """
    Get notifications for the current community member
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of notifications
    """
    # Placeholder — returns empty list until Notification model is implemented
    return jsonify({'notifications': [], 'unread_count': 0}), 200


@community_bp.route('/community/notifications/<int:notification_id>', methods=['PATCH'])
@require_community
def community_mark_notification_read(notification_id):
    """
    Mark a notification as read
    ---
    tags:
      - Community
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: notification_id
        type: integer
        required: true
    responses:
      200:
        description: Notification marked as read
    """
    return jsonify({'message': 'Notification marked as read'}), 200
