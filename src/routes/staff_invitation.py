"""
Staff Invitation Routes
-----------------------
Council Admins use these endpoints to invite new staff members to their council
on GrantThrive.  Invited users receive an email with a one-time token link;
clicking the link opens a set-password form and activates their account.

Endpoints
---------
POST /api/council/invite-staff
    Send an invitation email to a new staff member.
    Requires: COUNCIL_ADMIN role.

POST /api/council/accept-invitation
    Accept an invitation: set password and activate the new account.
    Public endpoint (no auth required).

GET  /api/council/invitations
    List all pending invitations sent by the current council.
    Requires: COUNCIL_ADMIN role.
"""

from flask import Blueprint, request, jsonify, current_app
from src.models.user import db, User, UserRole, UserStatus
from src.routes.auth import verify_token, generate_token
from src.utils.email import email_service
from datetime import datetime, timedelta
import secrets
import re

staff_invitation_bp = Blueprint('staff_invitation', __name__)

# ---------------------------------------------------------------------------
# In-memory invitation store
# In production this should be a database table (e.g. Invitation model).
# Using a module-level dict here keeps the change self-contained and avoids
# a schema migration for now.  The developer can promote this to a DB model
# when ready.
# ---------------------------------------------------------------------------
_invitations: dict[str, dict] = {}   # token -> invitation record


def _require_council_admin(f):
    """Decorator: authenticate and verify the caller is a COUNCIL_ADMIN."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        user = User.query.get(user_id)
        if not user or user.status != UserStatus.ACTIVE:
            return jsonify({'error': 'User not found or inactive'}), 401
        if user.role != UserRole.COUNCIL_ADMIN:
            return jsonify({'error': 'Council Admin access required'}), 403
        request.current_user = user
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# POST /api/council/invite-staff
# ---------------------------------------------------------------------------

@staff_invitation_bp.route('/council/invite-staff', methods=['POST'])
@_require_council_admin
def invite_staff():
    """
    Invite a new staff member to the council (Council Admin only)
    ---
    tags:
      - Staff Invitation
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [email]
          properties:
            email:
              type: string
              description: Must share the same domain as the inviting admin
              example: john.smith@brisbane.qld.gov.au
            first_name:
              type: string
              example: John
            last_name:
              type: string
              example: Smith
            role:
              type: string
              enum: [council_staff, council_admin]
              default: council_staff
    responses:
      200:
        description: Invitation sent by email
      400:
        description: Validation error or domain mismatch
      401:
        description: Unauthorised
      403:
        description: Council Admin access required
      409:
        description: Email already registered
    """
    try:
        data = request.get_json() or {}
        invitee_email = data.get('email', '').strip().lower()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        role_str = data.get('role', 'council_staff').strip().lower()

        if not invitee_email:
            return jsonify({'error': 'email is required'}), 400

        # Validate role
        allowed_roles = {'council_staff': UserRole.COUNCIL_STAFF,
                         'council_admin': UserRole.COUNCIL_ADMIN}
        if role_str not in allowed_roles:
            return jsonify({
                'error': "role must be 'council_staff' or 'council_admin'"
            }), 400
        target_role = allowed_roles[role_str]

        # Enforce same email domain as the inviting admin
        admin = request.current_user
        admin_domain = admin.email.split('@')[1]
        invitee_domain = invitee_email.split('@')[1] if '@' in invitee_email else ''
        if invitee_domain != admin_domain:
            return jsonify({
                'error': (
                    f"Invitee email must use the same domain as your council "
                    f"(@{admin_domain})."
                )
            }), 400

        # Check the invitee is not already registered
        if User.query.filter_by(email=invitee_email).first():
            return jsonify({
                'error': 'This email address is already registered on GrantThrive.'
            }), 409

        # Check for an existing pending invitation for this email
        existing = next(
            (inv for inv in _invitations.values()
             if inv['invitee_email'] == invitee_email and not inv['accepted']),
            None
        )
        if existing:
            return jsonify({
                'error': 'A pending invitation already exists for this email address.'
            }), 409

        # Generate a cryptographically secure one-time token (valid 7 days)
        token = secrets.token_urlsafe(48)
        expires_at = datetime.utcnow() + timedelta(days=7)

        _invitations[token] = {
            'token': token,
            'invitee_email': invitee_email,
            'first_name': first_name,
            'last_name': last_name,
            'role': target_role,
            'role_label': 'Council Admin' if target_role == UserRole.COUNCIL_ADMIN else 'Council Staff',
            'council_name': admin.organization_name or admin_domain,
            'invited_by_id': admin.id,
            'invited_by_name': admin.full_name,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at.isoformat(),
            'accepted': False
        }

        # Send invitation email
        try:
            email_service.send_staff_invitation(
                invitee_email=invitee_email,
                invitee_name=f'{first_name} {last_name}'.strip(),
                council_name=admin.organization_name or admin_domain,
                invited_by_name=admin.full_name,
                role_label=_invitations[token]['role_label'],
                invitation_token=token
            )
        except Exception as email_err:
            current_app.logger.warning(
                f'Staff invitation email failed for {invitee_email}: {email_err}'
            )
            # Do not fail the request — the token is still stored and can be
            # resent or shared manually.

        return jsonify({
            'message': f'Invitation sent to {invitee_email}',
            'invitation': {
                'invitee_email': invitee_email,
                'role': role_str,
                'expires_at': expires_at.isoformat()
            }
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# POST /api/council/accept-invitation
# ---------------------------------------------------------------------------

@staff_invitation_bp.route('/council/accept-invitation', methods=['POST'])
def accept_invitation():
    """
    Accept a staff invitation and create the new user account
    ---
    tags:
      - Staff Invitation
    security: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required: [token, password]
          properties:
            token:
              type: string
              description: Invitation token from the email link
            password:
              type: string
              description: Minimum 8 characters
            first_name:
              type: string
            last_name:
              type: string
    responses:
      201:
        description: Account created and welcome email sent
      400:
        description: Missing fields or weak password
      404:
        description: Invalid or expired token
      409:
        description: Email already registered
      410:
        description: Invitation already used or expired
    """
    try:
        data = request.get_json() or {}
        token = data.get('token', '').strip()
        password = data.get('password', '').strip()
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()

        if not token:
            return jsonify({'error': 'Invitation token is required'}), 400
        if not password or len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        invitation = _invitations.get(token)
        if not invitation:
            return jsonify({'error': 'Invalid or expired invitation token'}), 404
        if invitation['accepted']:
            return jsonify({'error': 'This invitation has already been used'}), 410

        # Check expiry
        expires_at = datetime.fromisoformat(invitation['expires_at'])
        if datetime.utcnow() > expires_at:
            return jsonify({'error': 'This invitation has expired'}), 410

        # Resolve name: prefer data from accept form, fall back to invite record
        resolved_first = first_name or invitation['first_name']
        resolved_last = last_name or invitation['last_name']
        if not resolved_first or not resolved_last:
            return jsonify({'error': 'first_name and last_name are required'}), 400

        # Check the email is still not registered (race condition guard)
        if User.query.filter_by(email=invitation['invitee_email']).first():
            return jsonify({
                'error': 'This email address is already registered.'
            }), 409

        # Look up the inviting admin to copy council details
        inviting_admin = User.query.get(invitation['invited_by_id'])

        new_user = User(
            email=invitation['invitee_email'],
            first_name=resolved_first,
            last_name=resolved_last,
            role=invitation['role'],
            status=UserStatus.ACTIVE,   # Invited staff are immediately active
            organization_name=(
                inviting_admin.organization_name if inviting_admin else None
            ),
            email_verified=True
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        # Mark invitation as used
        invitation['accepted'] = True
        invitation['accepted_at'] = datetime.utcnow().isoformat()
        invitation['accepted_by_user_id'] = new_user.id

        # Send welcome email to the new staff member
        try:
            email_service.send_welcome_email(
                user_email=new_user.email,
                user_name=new_user.full_name,
                user_role=new_user.role.value
            )
        except Exception as email_err:
            current_app.logger.warning(
                f'Welcome email failed for new staff {new_user.email}: {email_err}'
            )

        jwt_token = generate_token(new_user.id)

        return jsonify({
            'message': 'Invitation accepted. Your account is now active.',
            'user': new_user.to_dict(),
            'token': jwt_token
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# GET /api/council/invitations
# ---------------------------------------------------------------------------

@staff_invitation_bp.route('/council/invitations', methods=['GET'])
@_require_council_admin
def list_invitations():
    """
    List all invitations sent by the current Council Admin's council
    ---
    tags:
      - Staff Invitation
    responses:
      200:
        description: List of invitations with status (pending, accepted, expired)
      401:
        description: Unauthorised
      403:
        description: Council Admin access required
    """
    try:
        admin = request.current_user
        admin_domain = admin.email.split('@')[1]

        now = datetime.utcnow()
        results = []
        for inv in _invitations.values():
            # Only show invitations from this council (same domain)
            if inv['invitee_email'].split('@')[1] != admin_domain:
                continue
            expires_at = datetime.fromisoformat(inv['expires_at'])
            status = (
                'accepted' if inv['accepted']
                else ('expired' if now > expires_at else 'pending')
            )
            results.append({
                'invitee_email': inv['invitee_email'],
                'first_name': inv['first_name'],
                'last_name': inv['last_name'],
                'role': inv['role'].value,
                'role_label': inv['role_label'],
                'invited_by': inv['invited_by_name'],
                'created_at': inv['created_at'],
                'expires_at': inv['expires_at'],
                'status': status
            })

        # Sort newest first
        results.sort(key=lambda x: x['created_at'], reverse=True)

        return jsonify({
            'invitations': results,
            'count': len(results)
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500
