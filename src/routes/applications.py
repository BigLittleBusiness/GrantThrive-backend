from flask import Blueprint, request, jsonify
from src.models.user import db, User
from src.models.grant import Grant
from src.models.application import Application, ApplicationStatus
from src.routes.auth import verify_token
from datetime import datetime
import json

applications_bp = Blueprint('applications', __name__)

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

@applications_bp.route('/applications', methods=['GET'])
@require_auth
def get_applications():
    """Get applications (filtered by user role)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        status = request.args.get('status')
        grant_id = request.args.get('grant_id', type=int)
        
        # Build query based on user role
        if request.current_user.is_admin:
            # Admins see all applications
            query = Application.query
        else:
            # Regular users see only their applications
            query = Application.query.filter(Application.applicant_id == request.current_user.id)
        
        # Apply filters
        if status:
            try:
                status_enum = ApplicationStatus(status)
                query = query.filter(Application.status == status_enum)
            except ValueError:
                pass
        
        if grant_id:
            query = query.filter(Application.grant_id == grant_id)
        
        # Order by creation date (newest first)
        query = query.order_by(Application.created_at.desc())
        
        # Paginate
        applications = query.paginate(
            page=page,
            per_page=per_page,
            error_out=False
        )
        
        # Prepare response data
        app_data = []
        for app in applications.items:
            app_dict = app.to_dict()
            
            # Add grant information
            if app.grant:
                app_dict['grant'] = {
                    'id': app.grant.id,
                    'title': app.grant.title,
                    'funding_amount': app.grant.funding_amount,
                    'close_date': app.grant.close_date.isoformat() if app.grant.close_date else None
                }
            
            # Add applicant information (for admins)
            if request.current_user.is_admin and app.applicant:
                app_dict['applicant'] = {
                    'id': app.applicant.id,
                    'name': app.applicant.full_name,
                    'email': app.applicant.email,
                    'organization': app.applicant.organization_name
                }
            
            app_data.append(app_dict)
        
        return jsonify({
            'applications': app_data,
            'pagination': {
                'page': applications.page,
                'pages': applications.pages,
                'per_page': applications.per_page,
                'total': applications.total,
                'has_next': applications.has_next,
                'has_prev': applications.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications/<int:application_id>', methods=['GET'])
@require_auth
def get_application(application_id):
    """Get specific application by ID"""
    try:
        application = Application.query.get_or_404(application_id)
        
        # Check permissions
        if not request.current_user.is_admin and application.applicant_id != request.current_user.id:
            return jsonify({'error': 'Permission denied'}), 403
        
        app_data = application.to_dict()
        
        # Add grant information
        if application.grant:
            app_data['grant'] = application.grant.to_dict()
        
        # Add applicant information (for admins)
        if request.current_user.is_admin and application.applicant:
            app_data['applicant'] = application.applicant.to_dict()
        
        # Add reviewer information
        if application.reviewer:
            app_data['reviewer'] = {
                'name': application.reviewer.full_name,
                'email': application.reviewer.email
            }
        
        return jsonify(app_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications', methods=['POST'])
@require_auth
def create_application():
    """Create new application"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = [
            'grant_id', 'organization_name', 'contact_person', 'contact_email',
            'project_title', 'project_description', 'requested_amount'
        ]
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Validate grant exists and is open
        grant = Grant.query.get(data['grant_id'])
        if not grant:
            return jsonify({'error': 'Grant not found'}), 404
        
        if grant.status.value not in ['open', 'closing_soon']:
            return jsonify({'error': 'Grant is not accepting applications'}), 400
        
        # Check if user already has an application for this grant
        existing_app = Application.query.filter_by(
            grant_id=data['grant_id'],
            applicant_id=request.current_user.id
        ).first()
        
        if existing_app:
            return jsonify({'error': 'You have already applied for this grant'}), 400
        
        # Create application
        application = Application(
            grant_id=data['grant_id'],
            applicant_id=request.current_user.id,
            organization_name=data['organization_name'],
            organization_type=data.get('organization_type'),
            abn_acn=data.get('abn_acn'),
            contact_person=data['contact_person'],
            contact_email=data['contact_email'],
            contact_phone=data.get('contact_phone'),
            address_line1=data.get('address_line1'),
            address_line2=data.get('address_line2'),
            city=data.get('city'),
            state=data.get('state'),
            postcode=data.get('postcode'),
            country=data.get('country', 'Australia'),
            project_title=data['project_title'],
            project_description=data['project_description'],
            project_objectives=data.get('project_objectives'),
            project_timeline=data.get('project_timeline'),
            requested_amount=data['requested_amount'],
            total_project_cost=data.get('total_project_cost'),
            other_funding_sources=data.get('other_funding_sources'),
            budget_breakdown=json.dumps(data.get('budget_breakdown', [])),
            expected_outcomes=data.get('expected_outcomes'),
            target_beneficiaries=data.get('target_beneficiaries'),
            community_impact=data.get('community_impact'),
            status=ApplicationStatus.DRAFT,
            declaration_accepted=data.get('declaration_accepted', False)
        )
        
        db.session.add(application)
        
        # Update grant application count
        grant.application_count += 1
        
        db.session.commit()
        
        return jsonify({
            'message': 'Application created successfully',
            'application': application.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications/<int:application_id>', methods=['PUT'])
@require_auth
def update_application(application_id):
    """Update existing application"""
    try:
        application = Application.query.get_or_404(application_id)
        
        # Check permissions
        if not request.current_user.is_admin and application.applicant_id != request.current_user.id:
            return jsonify({'error': 'Permission denied'}), 403
        
        # Check if application can be edited
        if application.status not in [ApplicationStatus.DRAFT, ApplicationStatus.REQUIRES_CLARIFICATION]:
            return jsonify({'error': 'Application cannot be edited in current status'}), 400
        
        data = request.get_json()
        
        # Update fields
        updatable_fields = [
            'organization_name', 'organization_type', 'abn_acn',
            'contact_person', 'contact_email', 'contact_phone',
            'address_line1', 'address_line2', 'city', 'state', 'postcode', 'country',
            'project_title', 'project_description', 'project_objectives', 'project_timeline',
            'requested_amount', 'total_project_cost', 'other_funding_sources',
            'expected_outcomes', 'target_beneficiaries', 'community_impact',
            'declaration_accepted'
        ]
        
        for field in updatable_fields:
            if field in data:
                if field == 'budget_breakdown':
                    setattr(application, field, json.dumps(data[field]))
                else:
                    setattr(application, field, data[field])
        
        application.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Application updated successfully',
            'application': application.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications/<int:application_id>/submit', methods=['POST'])
@require_auth
def submit_application(application_id):
    """Submit application for review"""
    try:
        application = Application.query.get_or_404(application_id)
        
        # Check permissions
        if application.applicant_id != request.current_user.id:
            return jsonify({'error': 'Permission denied'}), 403
        
        # Check if application can be submitted
        if application.status != ApplicationStatus.DRAFT:
            return jsonify({'error': 'Application has already been submitted'}), 400
        
        # Validate required fields for submission
        required_fields = [
            'organization_name', 'contact_person', 'contact_email',
            'project_title', 'project_description', 'requested_amount'
        ]
        
        for field in required_fields:
            if not getattr(application, field):
                return jsonify({'error': f'{field} is required for submission'}), 400
        
        if not application.declaration_accepted:
            return jsonify({'error': 'Declaration must be accepted'}), 400
        
        # Submit application
        application.status = ApplicationStatus.SUBMITTED
        application.submitted_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Application submitted successfully',
            'application': application.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications/<int:application_id>/review', methods=['POST'])
@require_auth
def review_application(application_id):
    """Review application (admin only)"""
    try:
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        application = Application.query.get_or_404(application_id)
        data = request.get_json()
        
        # Validate status
        new_status = data.get('status')
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        try:
            status_enum = ApplicationStatus(new_status)
        except ValueError:
            return jsonify({'error': 'Invalid status'}), 400
        
        # Update application
        application.status = status_enum
        application.reviewed_by = request.current_user.id
        application.reviewed_at = datetime.utcnow()
        application.review_notes = data.get('review_notes')
        
        db.session.commit()
        
        return jsonify({
            'message': 'Application reviewed successfully',
            'application': application.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@applications_bp.route('/applications/stats', methods=['GET'])
@require_auth
def get_application_stats():
    """Get application statistics"""
    try:
        if request.current_user.is_admin:
            # Admin sees all stats
            total_applications = Application.query.count()
            pending_review = Application.query.filter(
                Application.status == ApplicationStatus.SUBMITTED
            ).count()
            approved = Application.query.filter(
                Application.status == ApplicationStatus.APPROVED
            ).count()
            rejected = Application.query.filter(
                Application.status == ApplicationStatus.REJECTED
            ).count()
        else:
            # Users see their own stats
            user_apps = Application.query.filter(Application.applicant_id == request.current_user.id)
            total_applications = user_apps.count()
            pending_review = user_apps.filter(
                Application.status == ApplicationStatus.SUBMITTED
            ).count()
            approved = user_apps.filter(
                Application.status == ApplicationStatus.APPROVED
            ).count()
            rejected = user_apps.filter(
                Application.status == ApplicationStatus.REJECTED
            ).count()
        
        return jsonify({
            'total_applications': total_applications,
            'pending_review': pending_review,
            'approved': approved,
            'rejected': rejected,
            'success_rate': (approved / total_applications * 100) if total_applications > 0 else 0
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

