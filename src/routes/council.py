"""
GrantThrive — Council API Routes
=================================
All endpoints under /api/council/ are exclusively for authenticated
COUNCIL_STAFF and COUNCIL_ADMIN users. Community members cannot access
these routes.

Endpoints:
  GET    /api/council/profile                       — Get own profile
  PUT    /api/council/profile                       — Update own profile
  GET    /api/council/dashboard                     — Dashboard metrics
  GET    /api/council/grants                        — List council's grants
  GET    /api/council/grants/<id>                   — Get grant detail
  POST   /api/council/grants                        — Create a grant (admin only)
  PUT    /api/council/grants/<id>                   — Update a grant (admin only)
  DELETE /api/council/grants/<id>                   — Delete a grant (admin only)
  GET    /api/council/applications                  — List applications for council's grants
  GET    /api/council/applications/<id>             — Get application detail
  PUT    /api/council/applications/<id>/status      — Update application status
  GET    /api/council/staff                         — List council staff (admin only)
  POST   /api/council/staff/invite                  — Invite a staff member (admin only)
  GET    /api/council/stats                         — Council-level stats
  GET    /api/council/notifications                 — Get own notifications
"""

from flask import Blueprint, request, jsonify
from functools import wraps
from src.models.user import db, User, UserRole, UserStatus
from src.models.grant import Grant, GrantStatus
from src.models.application import Application, ApplicationStatus
import jwt
import os
from datetime import datetime

council_bp = Blueprint('council', __name__)


# ─── Auth decorators ─────────────────────────────────────────────────────────

def require_council(f):
    """Require a valid JWT belonging to COUNCIL_STAFF or COUNCIL_ADMIN."""
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
            if user.role not in [UserRole.COUNCIL_STAFF, UserRole.COUNCIL_ADMIN]:
                return jsonify({'error': 'Access restricted to council users'}), 403
            request.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


def require_council_admin(f):
    """Require a valid JWT belonging to COUNCIL_ADMIN only."""
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
            if user.role != UserRole.COUNCIL_ADMIN:
                return jsonify({'error': 'Access restricted to council administrators'}), 403
            request.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated


# ─── Profile ─────────────────────────────────────────────────────────────────

@council_bp.route('/council/profile', methods=['GET'])
@require_council
def get_council_profile():
    """
    Get council user profile
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    responses:
      200:
        description: Council user profile
    """
    user = request.current_user
    return jsonify({'user': user.to_dict()}), 200


@council_bp.route('/council/profile', methods=['PUT'])
@require_council
def update_council_profile():
    """
    Update council user profile
    ---
    tags:
      - Council
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
            position:
              type: string
    responses:
      200:
        description: Profile updated
    """
    user = request.current_user
    data = request.get_json() or {}
    allowed = ['first_name', 'last_name', 'phone', 'position', 'department']
    for field in allowed:
        if field in data:
            setattr(user, field, data[field])
    user.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({'message': 'Profile updated', 'user': user.to_dict()}), 200


# ─── Dashboard ────────────────────────────────────────────────────────────────

@council_bp.route('/council/dashboard', methods=['GET'])
@require_council
def council_dashboard():
    """
    Get dashboard metrics for the council user
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    responses:
      200:
        description: Council dashboard metrics
    """
    user = request.current_user
    council_domain = user.email.split('@')[1] if '@' in user.email else None

    # Grants created by users from the same council domain
    council_user_ids = []
    if council_domain:
        council_users = User.query.filter(
            User.email.like(f'%@{council_domain}'),
            User.role.in_([UserRole.COUNCIL_ADMIN, UserRole.COUNCIL_STAFF])
        ).all()
        council_user_ids = [u.id for u in council_users]

    total_grants = Grant.query.filter(
        Grant.created_by.in_(council_user_ids)
    ).count() if council_user_ids else 0

    active_grants = Grant.query.filter(
        Grant.created_by.in_(council_user_ids),
        Grant.status == GrantStatus.PUBLISHED
    ).count() if council_user_ids else 0

    grant_ids = [g.id for g in Grant.query.filter(
        Grant.created_by.in_(council_user_ids)
    ).all()] if council_user_ids else []

    total_applications = Application.query.filter(
        Application.grant_id.in_(grant_ids)
    ).count() if grant_ids else 0

    pending_review = Application.query.filter(
        Application.grant_id.in_(grant_ids),
        Application.status == ApplicationStatus.SUBMITTED
    ).count() if grant_ids else 0

    approved = Application.query.filter(
        Application.grant_id.in_(grant_ids),
        Application.status == ApplicationStatus.APPROVED
    ).count() if grant_ids else 0

    return jsonify({
        'metrics': {
            'total_grants': total_grants,
            'active_grants': active_grants,
            'total_applications': total_applications,
            'pending_review': pending_review,
            'approved_applications': approved
        }
    }), 200


# ─── Grants ───────────────────────────────────────────────────────────────────

@council_bp.route('/council/grants', methods=['GET'])
@require_council
def council_get_grants():
    """
    List grants belonging to this council
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: status
        type: string
      - in: query
        name: page
        type: integer
      - in: query
        name: per_page
        type: integer
    responses:
      200:
        description: List of council grants
    """
    user = request.current_user
    council_domain = user.email.split('@')[1] if '@' in user.email else None
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    status_filter = request.args.get('status')

    council_user_ids = []
    if council_domain:
        council_users = User.query.filter(
            User.email.like(f'%@{council_domain}'),
            User.role.in_([UserRole.COUNCIL_ADMIN, UserRole.COUNCIL_STAFF])
        ).all()
        council_user_ids = [u.id for u in council_users]

    query = Grant.query.filter(Grant.created_by.in_(council_user_ids)) if council_user_ids else Grant.query.filter_by(id=None)

    if status_filter:
        try:
            query = query.filter(Grant.status == GrantStatus(status_filter))
        except ValueError:
            pass

    pagination = query.order_by(Grant.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'grants': [g.to_dict() for g in pagination.items],
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    }), 200


@council_bp.route('/council/grants/<int:grant_id>', methods=['GET'])
@require_council
def council_get_grant(grant_id):
    """
    Get a single grant's detail (council view)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: grant_id
        type: integer
        required: true
    responses:
      200:
        description: Grant detail
      404:
        description: Grant not found
    """
    grant = Grant.query.get(grant_id)
    if not grant:
        return jsonify({'error': 'Grant not found'}), 404
    return jsonify({'grant': grant.to_dict()}), 200


@council_bp.route('/council/grants', methods=['POST'])
@require_council_admin
def council_create_grant():
    """
    Create a new grant (council admin only)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - title
            - description
            - total_budget
            - open_date
            - close_date
          properties:
            title:
              type: string
            description:
              type: string
            total_budget:
              type: number
            open_date:
              type: string
              format: date
            close_date:
              type: string
              format: date
            category:
              type: string
            max_grant_amount:
              type: number
    responses:
      201:
        description: Grant created
      400:
        description: Validation error
    """
    user = request.current_user
    data = request.get_json() or {}

    required = ['title', 'description', 'total_budget', 'open_date', 'close_date']
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing required fields: {", ".join(missing)}'}), 400

    grant = Grant(
        title=data['title'],
        description=data['description'],
        total_budget=data['total_budget'],
        open_date=datetime.strptime(data['open_date'], '%Y-%m-%d').date(),
        close_date=datetime.strptime(data['close_date'], '%Y-%m-%d').date(),
        category=data.get('category', ''),
        max_grant_amount=data.get('max_grant_amount'),
        status=GrantStatus.DRAFT,
        created_by=user.id,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(grant)
    db.session.commit()

    return jsonify({
        'message': 'Grant created successfully',
        'grant': grant.to_dict()
    }), 201


@council_bp.route('/council/grants/<int:grant_id>', methods=['PUT'])
@require_council_admin
def council_update_grant(grant_id):
    """
    Update a grant (council admin only)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: grant_id
        type: integer
        required: true
      - in: body
        name: body
        schema:
          type: object
    responses:
      200:
        description: Grant updated
      404:
        description: Grant not found
    """
    grant = Grant.query.get(grant_id)
    if not grant:
        return jsonify({'error': 'Grant not found'}), 404

    data = request.get_json() or {}
    allowed = ['title', 'description', 'total_budget', 'category',
               'max_grant_amount', 'status', 'open_date', 'close_date']
    for field in allowed:
        if field in data:
            if field in ['open_date', 'close_date']:
                setattr(grant, field, datetime.strptime(data[field], '%Y-%m-%d').date())
            elif field == 'status':
                try:
                    setattr(grant, field, GrantStatus(data[field]))
                except ValueError:
                    pass
            else:
                setattr(grant, field, data[field])
    grant.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({'message': 'Grant updated', 'grant': grant.to_dict()}), 200


@council_bp.route('/council/grants/<int:grant_id>', methods=['DELETE'])
@require_council_admin
def council_delete_grant(grant_id):
    """
    Delete a grant (council admin only)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: grant_id
        type: integer
        required: true
    responses:
      200:
        description: Grant deleted
      404:
        description: Grant not found
    """
    grant = Grant.query.get(grant_id)
    if not grant:
        return jsonify({'error': 'Grant not found'}), 404
    db.session.delete(grant)
    db.session.commit()
    return jsonify({'message': 'Grant deleted successfully'}), 200


# ─── Applications ─────────────────────────────────────────────────────────────

@council_bp.route('/council/applications', methods=['GET'])
@require_council
def council_get_applications():
    """
    List all applications for this council's grants
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: grant_id
        type: integer
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
    council_domain = user.email.split('@')[1] if '@' in user.email else None
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 20, type=int), 100)
    grant_id_filter = request.args.get('grant_id', type=int)
    status_filter = request.args.get('status')

    council_user_ids = []
    if council_domain:
        council_users = User.query.filter(
            User.email.like(f'%@{council_domain}'),
            User.role.in_([UserRole.COUNCIL_ADMIN, UserRole.COUNCIL_STAFF])
        ).all()
        council_user_ids = [u.id for u in council_users]

    grant_ids = [g.id for g in Grant.query.filter(
        Grant.created_by.in_(council_user_ids)
    ).all()] if council_user_ids else []

    query = Application.query.filter(Application.grant_id.in_(grant_ids)) if grant_ids else Application.query.filter_by(id=None)

    if grant_id_filter:
        query = query.filter_by(grant_id=grant_id_filter)
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


@council_bp.route('/council/applications/<int:application_id>', methods=['GET'])
@require_council
def council_get_application(application_id):
    """
    Get a single application detail (council view)
    ---
    tags:
      - Council
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
      404:
        description: Application not found
    """
    application = Application.query.get(application_id)
    if not application:
        return jsonify({'error': 'Application not found'}), 404
    return jsonify({'application': application.to_dict()}), 200


@council_bp.route('/council/applications/<int:application_id>/status', methods=['PUT'])
@require_council
def council_update_application_status(application_id):
    """
    Update the status of an application (approve, reject, request info)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    parameters:
      - in: path
        name: application_id
        type: integer
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - status
          properties:
            status:
              type: string
              enum: [approved, rejected, under_review, information_requested]
            notes:
              type: string
    responses:
      200:
        description: Status updated
      400:
        description: Invalid status
      404:
        description: Application not found
    """
    application = Application.query.get(application_id)
    if not application:
        return jsonify({'error': 'Application not found'}), 404

    data = request.get_json() or {}
    new_status = data.get('status')
    if not new_status:
        return jsonify({'error': 'status is required'}), 400

    try:
        application.status = ApplicationStatus(new_status)
    except ValueError:
        return jsonify({'error': f'Invalid status: {new_status}'}), 400

    if data.get('notes'):
        application.review_notes = data['notes']
    application.updated_at = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'message': 'Application status updated',
        'application': application.to_dict()
    }), 200


# ─── Staff management (admin only) ───────────────────────────────────────────

@council_bp.route('/council/staff', methods=['GET'])
@require_council_admin
def council_get_staff():
    """
    List all staff members for this council (admin only)
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of council staff
    """
    user = request.current_user
    council_domain = user.email.split('@')[1] if '@' in user.email else None

    staff = []
    if council_domain:
        staff = User.query.filter(
            User.email.like(f'%@{council_domain}'),
            User.role.in_([UserRole.COUNCIL_ADMIN, UserRole.COUNCIL_STAFF])
        ).order_by(User.created_at.desc()).all()

    return jsonify({
        'staff': [u.to_dict() for u in staff],
        'total': len(staff)
    }), 200


# ─── Stats ────────────────────────────────────────────────────────────────────

@council_bp.route('/council/stats', methods=['GET'])
@require_council
def council_stats():
    """
    Get aggregate statistics for this council
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    responses:
      200:
        description: Council statistics
    """
    user = request.current_user
    council_domain = user.email.split('@')[1] if '@' in user.email else None

    council_user_ids = []
    if council_domain:
        council_users = User.query.filter(
            User.email.like(f'%@{council_domain}'),
            User.role.in_([UserRole.COUNCIL_ADMIN, UserRole.COUNCIL_STAFF])
        ).all()
        council_user_ids = [u.id for u in council_users]

    grant_ids = [g.id for g in Grant.query.filter(
        Grant.created_by.in_(council_user_ids)
    ).all()] if council_user_ids else []

    stats = {
        'grants': {
            'total': Grant.query.filter(Grant.created_by.in_(council_user_ids)).count() if council_user_ids else 0,
            'published': Grant.query.filter(Grant.created_by.in_(council_user_ids), Grant.status == GrantStatus.PUBLISHED).count() if council_user_ids else 0,
            'draft': Grant.query.filter(Grant.created_by.in_(council_user_ids), Grant.status == GrantStatus.DRAFT).count() if council_user_ids else 0,
            'closed': Grant.query.filter(Grant.created_by.in_(council_user_ids), Grant.status == GrantStatus.CLOSED).count() if council_user_ids else 0,
        },
        'applications': {
            'total': Application.query.filter(Application.grant_id.in_(grant_ids)).count() if grant_ids else 0,
            'submitted': Application.query.filter(Application.grant_id.in_(grant_ids), Application.status == ApplicationStatus.SUBMITTED).count() if grant_ids else 0,
            'approved': Application.query.filter(Application.grant_id.in_(grant_ids), Application.status == ApplicationStatus.APPROVED).count() if grant_ids else 0,
            'rejected': Application.query.filter(Application.grant_id.in_(grant_ids), Application.status == ApplicationStatus.REJECTED).count() if grant_ids else 0,
        },
        'staff_count': len(council_user_ids)
    }

    return jsonify({'stats': stats}), 200


# ─── Notifications ────────────────────────────────────────────────────────────

@council_bp.route('/council/notifications', methods=['GET'])
@require_council
def council_get_notifications():
    """
    Get notifications for the current council user
    ---
    tags:
      - Council
    security:
      - BearerAuth: []
    responses:
      200:
        description: List of notifications
    """
    return jsonify({'notifications': [], 'unread_count': 0}), 200
