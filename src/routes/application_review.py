from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from ..models.application import Application
from ..models.grant import Grant
from ..models.user import User, db
from ..utils.email import EmailService
import uuid

application_review_bp = Blueprint('application_review', __name__)

@application_review_bp.route('/api/applications/review/<grant_id>', methods=['GET'])
@jwt_required()
def get_applications_for_review(grant_id):
    """Get all applications for a specific grant for review"""
    try:
        current_user_id = get_jwt_identity()
        
        # Verify user has permission to review this grant
        grant = Grant.query.get(grant_id)
        if not grant:
            return jsonify({'success': False, 'message': 'Grant not found'}), 404
        
        # Check if user is authorized to review (grant creator or assigned reviewer)
        user = User.query.get(current_user_id)
        if grant.created_by != current_user_id and user.role not in ['council_admin', 'council_staff']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Get applications for this grant
        applications = Application.query.filter_by(grant_id=grant_id).all()
        
        applications_data = []
        for app in applications:
            applicant = User.query.get(app.applicant_id)
            
            applications_data.append({
                'id': app.id,
                'applicantName': f"{applicant.first_name} {applicant.last_name}",
                'organization': applicant.organization,
                'submissionDate': app.submitted_at.isoformat() if app.submitted_at else None,
                'status': app.status,
                'score': app.final_score,
                'amount': app.requested_amount,
                'projectTitle': app.project_title,
                'category': grant.category,
                'priority': app.priority or 'medium',
                'reviewers': app.assigned_reviewers or [],
                'documents': app.documents or [],
                'summary': app.project_description[:200] + '...' if app.project_description else '',
                'reviewData': app.review_data or {},
                'comments': app.review_comments or []
            })
        
        # Calculate analytics
        total_apps = len(applications_data)
        under_review = len([app for app in applications_data if app['status'] == 'under_review'])
        approved = len([app for app in applications_data if app['status'] == 'approved'])
        declined = len([app for app in applications_data if app['status'] == 'declined'])
        
        analytics = {
            'underReview': round((under_review / total_apps * 100)) if total_apps > 0 else 0,
            'approved': round((approved / total_apps * 100)) if total_apps > 0 else 0,
            'declined': round((declined / total_apps * 100)) if total_apps > 0 else 0,
            'commonThemes': extract_common_themes(applications_data),
            'recommendation': generate_recommendation(applications_data)
        }
        
        return jsonify({
            'success': True,
            'applications': applications_data,
            'analytics': analytics,
            'grant': {
                'id': grant.id,
                'title': grant.title,
                'category': grant.category,
                'total_funding': grant.total_funding
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@application_review_bp.route('/api/applications/review/<application_id>/score', methods=['POST'])
@jwt_required()
def score_application(application_id):
    """Submit scoring for an application"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        application = Application.query.get(application_id)
        if not application:
            return jsonify({'success': False, 'message': 'Application not found'}), 404
        
        # Verify user has permission to review
        user = User.query.get(current_user_id)
        if user.role not in ['council_admin', 'council_staff']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Update application with scoring data
        scores = data.get('scores', {})
        comments = data.get('comments', '')
        recommendation = data.get('recommendation', '')
        
        # Calculate weighted total score
        scoring_criteria = [
            {'key': 'impact', 'weight': 30},
            {'key': 'feasibility', 'weight': 25},
            {'key': 'budget', 'weight': 20},
            {'key': 'sustainability', 'weight': 15},
            {'key': 'innovation', 'weight': 10}
        ]
        
        total_score = 0
        for criteria in scoring_criteria:
            score = scores.get(criteria['key'], 0)
            total_score += score * criteria['weight'] / 100
        
        # Update application
        if not application.review_data:
            application.review_data = {}
        
        application.review_data[current_user_id] = {
            'scores': scores,
            'total_score': total_score,
            'comments': comments,
            'recommendation': recommendation,
            'reviewed_at': datetime.utcnow().isoformat(),
            'reviewer_name': f"{user.first_name} {user.last_name}"
        }
        
        # If this is the final review, update status and final score
        if recommendation in ['approve', 'decline']:
            application.status = 'approved' if recommendation == 'approve' else 'declined'
            application.final_score = round(total_score, 1)
            application.reviewed_at = datetime.utcnow()
            application.reviewed_by = current_user_id
        
        application.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Send notification to applicant if decision made
        if recommendation in ['approve', 'decline']:
            applicant = User.query.get(application.applicant_id)
            grant = Grant.query.get(application.grant_id)
            
            email_service = EmailService()
            decision_text = 'approved' if recommendation == 'approve' else 'declined'
            
            email_service.send_email(
                to_email=applicant.email,
                subject=f'Grant Application Decision: {grant.title}',
                html_content=f'''
                <h2>Grant Application Decision</h2>
                <p>Dear {applicant.first_name} {applicant.last_name},</p>
                <p>We have completed the review of your grant application:</p>
                <ul>
                    <li><strong>Grant:</strong> {grant.title}</li>
                    <li><strong>Project:</strong> {application.project_title}</li>
                    <li><strong>Decision:</strong> {decision_text.title()}</li>
                    <li><strong>Score:</strong> {round(total_score, 1)}/10</li>
                    {f'<li><strong>Amount:</strong> ${application.requested_amount:,.2f}</li>' if recommendation == 'approve' else ''}
                </ul>
                <p><strong>Comments:</strong> {comments}</p>
                <p>Best regards,<br>GrantThrive Platform</p>
                '''
            )
        
        return jsonify({
            'success': True,
            'message': 'Review submitted successfully',
            'total_score': round(total_score, 1),
            'status': application.status
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@application_review_bp.route('/api/applications/review/<application_id>/assign-reviewers', methods=['POST'])
@jwt_required()
def assign_reviewers(application_id):
    """Assign reviewers to an application"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        application = Application.query.get(application_id)
        if not application:
            return jsonify({'success': False, 'message': 'Application not found'}), 404
        
        # Verify user has permission (admin only)
        user = User.query.get(current_user_id)
        if user.role != 'council_admin':
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        reviewers = data.get('reviewers', [])
        
        # Validate reviewers exist and have appropriate roles
        for reviewer_id in reviewers:
            reviewer = User.query.get(reviewer_id)
            if not reviewer or reviewer.role not in ['council_admin', 'council_staff']:
                return jsonify({'success': False, 'message': f'Invalid reviewer: {reviewer_id}'}), 400
        
        application.assigned_reviewers = reviewers
        application.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Send notifications to assigned reviewers
        grant = Grant.query.get(application.grant_id)
        applicant = User.query.get(application.applicant_id)
        
        email_service = EmailService()
        for reviewer_id in reviewers:
            reviewer = User.query.get(reviewer_id)
            email_service.send_email(
                to_email=reviewer.email,
                subject=f'Application Review Assignment: {grant.title}',
                html_content=f'''
                <h2>Application Review Assignment</h2>
                <p>Dear {reviewer.first_name} {reviewer.last_name},</p>
                <p>You have been assigned to review a grant application:</p>
                <ul>
                    <li><strong>Grant:</strong> {grant.title}</li>
                    <li><strong>Project:</strong> {application.project_title}</li>
                    <li><strong>Applicant:</strong> {applicant.first_name} {applicant.last_name}</li>
                    <li><strong>Organization:</strong> {applicant.organization}</li>
                    <li><strong>Due Date:</strong> {(datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d')}</li>
                </ul>
                <p>Please review the application at: /applications/review/{application.id}</p>
                <p>Best regards,<br>GrantThrive Platform</p>
                '''
            )
        
        return jsonify({
            'success': True,
            'message': 'Reviewers assigned successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@application_review_bp.route('/api/applications/review/<application_id>/priority', methods=['POST'])
@jwt_required()
def set_application_priority(application_id):
    """Set priority level for an application"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        application = Application.query.get(application_id)
        if not application:
            return jsonify({'success': False, 'message': 'Application not found'}), 404
        
        # Verify user has permission
        user = User.query.get(current_user_id)
        if user.role not in ['council_admin', 'council_staff']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        priority = data.get('priority')
        if priority not in ['high', 'medium', 'low']:
            return jsonify({'success': False, 'message': 'Invalid priority level'}), 400
        
        application.priority = priority
        application.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Priority updated successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@application_review_bp.route('/api/applications/review/<application_id>/comments', methods=['POST'])
@jwt_required()
def add_review_comment(application_id):
    """Add a comment to an application review"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        application = Application.query.get(application_id)
        if not application:
            return jsonify({'success': False, 'message': 'Application not found'}), 404
        
        user = User.query.get(current_user_id)
        comment_text = data.get('comment', '').strip()
        
        if not comment_text:
            return jsonify({'success': False, 'message': 'Comment text is required'}), 400
        
        # Add comment to application
        if not application.review_comments:
            application.review_comments = []
        
        comment = {
            'id': str(uuid.uuid4()),
            'user_id': current_user_id,
            'user_name': f"{user.first_name} {user.last_name}",
            'comment': comment_text,
            'timestamp': datetime.utcnow().isoformat(),
            'type': data.get('type', 'general')  # general, question, concern, etc.
        }
        
        application.review_comments.append(comment)
        application.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Comment added successfully',
            'comment': comment
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@application_review_bp.route('/api/applications/review/bulk-action', methods=['POST'])
@jwt_required()
def bulk_review_action():
    """Perform bulk actions on multiple applications"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Verify user has permission
        user = User.query.get(current_user_id)
        if user.role not in ['council_admin', 'council_staff']:
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        application_ids = data.get('application_ids', [])
        action = data.get('action')
        
        if not application_ids:
            return jsonify({'success': False, 'message': 'No applications selected'}), 400
        
        applications = Application.query.filter(Application.id.in_(application_ids)).all()
        
        if action == 'assign_reviewers':
            reviewers = data.get('reviewers', [])
            for app in applications:
                app.assigned_reviewers = reviewers
                app.updated_at = datetime.utcnow()
                
        elif action == 'set_priority':
            priority = data.get('priority')
            if priority not in ['high', 'medium', 'low']:
                return jsonify({'success': False, 'message': 'Invalid priority'}), 400
            for app in applications:
                app.priority = priority
                app.updated_at = datetime.utcnow()
                
        elif action == 'update_status':
            status = data.get('status')
            if status not in ['submitted', 'under_review', 'approved', 'declined']:
                return jsonify({'success': False, 'message': 'Invalid status'}), 400
            for app in applications:
                app.status = status
                app.updated_at = datetime.utcnow()
                
        else:
            return jsonify({'success': False, 'message': 'Invalid action'}), 400
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Bulk action completed for {len(applications)} applications'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

def extract_common_themes(applications):
    """Extract common themes from application data"""
    themes = {}
    
    for app in applications:
        # Simple keyword extraction from project titles and summaries
        text = f"{app['projectTitle']} {app['summary']}".lower()
        
        keywords = [
            'community', 'youth', 'education', 'environment', 'health',
            'arts', 'culture', 'sports', 'technology', 'innovation',
            'sustainability', 'development', 'engagement', 'support'
        ]
        
        for keyword in keywords:
            if keyword in text:
                themes[keyword] = themes.get(keyword, 0) + 1
    
    # Return top 3 themes
    sorted_themes = sorted(themes.items(), key=lambda x: x[1], reverse=True)
    return [theme[0].title() for theme in sorted_themes[:3]]

def generate_recommendation(applications):
    """Generate AI-powered recommendation based on application data"""
    if not applications:
        return "No applications to analyze"
    
    # Simple rule-based recommendations
    youth_apps = len([app for app in applications if 'youth' in app['projectTitle'].lower() or 'youth' in app['summary'].lower()])
    total_apps = len(applications)
    
    if youth_apps / total_apps > 0.3:
        return "Prioritize initiatives targeting at-risk youth"
    
    high_amount_apps = len([app for app in applications if app['amount'] > 30000])
    if high_amount_apps / total_apps > 0.4:
        return "Consider breaking large projects into phases"
    
    return "Focus on community engagement and sustainability metrics"

