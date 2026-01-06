from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime, timedelta
from ..models.grant import Grant
from ..models.user import User, db
from ..utils.email import EmailService
import uuid

grant_wizard_bp = Blueprint('grant_wizard', __name__)

@grant_wizard_bp.route('/api/grant-wizard/templates', methods=['GET'])
@jwt_required()
def get_grant_templates():
    """Get available grant templates"""
    templates = [
        {
            'id': 'community-development',
            'name': 'Community Development Grant',
            'description': 'Support community projects that enhance local wellbeing',
            'category': 'Community Development',
            'typical_amount': '5000-50000',
            'duration': '12 months',
            'required_documents': [
                'Organization Registration',
                'Project Budget',
                'Impact Assessment'
            ],
            'custom_questions': [
                {
                    'question': 'How will this project benefit the local community?',
                    'type': 'textarea',
                    'required': True
                },
                {
                    'question': 'What partnerships have you established for this project?',
                    'type': 'textarea',
                    'required': False
                }
            ]
        },
        {
            'id': 'youth-programs',
            'name': 'Youth Programs Initiative',
            'description': 'Programs designed to engage and support young people',
            'category': 'Youth Programs',
            'typical_amount': '2000-25000',
            'duration': '6-18 months',
            'required_documents': [
                'Organization Registration',
                'Project Budget',
                'Youth Engagement Plan',
                'Safety Protocols'
            ],
            'custom_questions': [
                {
                    'question': 'What age group will this program target?',
                    'type': 'text',
                    'required': True
                },
                {
                    'question': 'How many young people do you expect to participate?',
                    'type': 'number',
                    'required': True
                }
            ]
        },
        {
            'id': 'environmental',
            'name': 'Environmental Sustainability Fund',
            'description': 'Projects focused on environmental protection and sustainability',
            'category': 'Environmental Sustainability',
            'typical_amount': '10000-75000',
            'duration': '12-24 months',
            'required_documents': [
                'Organization Registration',
                'Project Budget',
                'Environmental Impact Assessment',
                'Sustainability Plan'
            ],
            'custom_questions': [
                {
                    'question': 'What environmental issue does this project address?',
                    'type': 'textarea',
                    'required': True
                },
                {
                    'question': 'How will you measure environmental impact?',
                    'type': 'textarea',
                    'required': True
                }
            ]
        },
        {
            'id': 'arts-culture',
            'name': 'Arts & Culture Grant',
            'description': 'Support for artistic and cultural initiatives',
            'category': 'Arts & Culture',
            'typical_amount': '1000-30000',
            'duration': '3-12 months',
            'required_documents': [
                'Organization Registration',
                'Project Budget',
                'Artistic Portfolio',
                'Venue Agreements'
            ],
            'custom_questions': [
                {
                    'question': 'Describe the artistic or cultural significance of your project',
                    'type': 'textarea',
                    'required': True
                },
                {
                    'question': 'How will you engage the community in this project?',
                    'type': 'textarea',
                    'required': True
                }
            ]
        }
    ]
    
    return jsonify({
        'success': True,
        'templates': templates
    })

@grant_wizard_bp.route('/api/grant-wizard/save-draft', methods=['POST'])
@jwt_required()
def save_grant_draft():
    """Save grant as draft"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        # Create new grant or update existing draft
        grant_id = data.get('grant_id')
        
        if grant_id:
            grant = Grant.query.filter_by(id=grant_id, created_by=current_user_id).first()
            if not grant:
                return jsonify({'success': False, 'message': 'Grant not found'}), 404
        else:
            grant = Grant()
            grant.id = str(uuid.uuid4())
            grant.created_by = current_user_id
            grant.created_at = datetime.utcnow()
        
        # Update grant fields
        grant.title = data.get('title', '')
        grant.category = data.get('category', '')
        grant.description = data.get('description', '')
        grant.eligibility_criteria = data.get('eligibilityCriteria', '')
        grant.required_documents = data.get('requiredDocuments', [])
        
        # Funding and dates
        grant.total_funding = float(data.get('totalFunding', 0)) if data.get('totalFunding') else None
        grant.max_application_amount = float(data.get('maxApplicationAmount', 0)) if data.get('maxApplicationAmount') else None
        grant.min_application_amount = float(data.get('minApplicationAmount', 0)) if data.get('minApplicationAmount') else None
        
        if data.get('applicationOpenDate'):
            grant.application_open_date = datetime.fromisoformat(data.get('applicationOpenDate'))
        if data.get('applicationCloseDate'):
            grant.application_close_date = datetime.fromisoformat(data.get('applicationCloseDate'))
        if data.get('fundingStartDate'):
            grant.funding_start_date = datetime.fromisoformat(data.get('fundingStartDate'))
        if data.get('fundingEndDate'):
            grant.funding_end_date = datetime.fromisoformat(data.get('fundingEndDate'))
        
        grant.assessment_period_weeks = int(data.get('assessmentPeriod', 6)) if data.get('assessmentPeriod') else 6
        
        # Application form settings
        grant.custom_questions = data.get('customQuestions', [])
        grant.budget_requirements = data.get('budgetRequirements', True)
        grant.project_timeline = data.get('projectTimeline', True)
        grant.impact_measurement = data.get('impactMeasurement', True)
        grant.partnership_details = data.get('partnershipDetails', False)
        
        # Review settings
        grant.review_committee = data.get('reviewCommittee', [])
        grant.scoring_criteria = data.get('scoringCriteria', [])
        grant.notification_settings = data.get('notificationSettings', {})
        
        grant.status = 'draft'
        grant.updated_at = datetime.utcnow()
        
        if not grant_id:
            db.session.add(grant)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Grant draft saved successfully',
            'grant_id': grant.id
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@grant_wizard_bp.route('/api/grant-wizard/publish', methods=['POST'])
@jwt_required()
def publish_grant():
    """Publish grant program"""
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        
        grant_id = data.get('grant_id')
        if not grant_id:
            return jsonify({'success': False, 'message': 'Grant ID required'}), 400
        
        grant = Grant.query.filter_by(id=grant_id, created_by=current_user_id).first()
        if not grant:
            return jsonify({'success': False, 'message': 'Grant not found'}), 404
        
        # Validate required fields
        required_fields = ['title', 'category', 'description', 'eligibility_criteria', 
                          'total_funding', 'application_open_date', 'application_close_date']
        
        for field in required_fields:
            if not getattr(grant, field):
                return jsonify({
                    'success': False, 
                    'message': f'Required field missing: {field}'
                }), 400
        
        # Validate review committee
        if not grant.review_committee or len(grant.review_committee) == 0:
            return jsonify({
                'success': False, 
                'message': 'At least one reviewer must be assigned'
            }), 400
        
        # Update grant status
        auto_publish = data.get('autoPublish', False)
        grant.status = 'published' if auto_publish else 'pending_review'
        grant.published_at = datetime.utcnow() if auto_publish else None
        grant.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        # Send notifications
        user = User.query.get(current_user_id)
        
        # Notify review committee
        if grant.notification_settings.get('emailCommittee', True):
            email_service = EmailService()
            for reviewer in grant.review_committee:
                email_service.send_email(
                    to_email=reviewer['email'],
                    subject=f'New Grant Program for Review: {grant.title}',
                    html_content=f'''
                    <h2>New Grant Program for Review</h2>
                    <p>Dear {reviewer['name']},</p>
                    <p>A new grant program has been created and requires your review:</p>
                    <ul>
                        <li><strong>Grant Title:</strong> {grant.title}</li>
                        <li><strong>Council:</strong> {user.organization}</li>
                        <li><strong>Review Deadline:</strong> {(datetime.utcnow() + timedelta(days=7)).strftime('%Y-%m-%d')}</li>
                    </ul>
                    <p>Please review the grant program at: /grants/{grant.id}</p>
                    <p>Best regards,<br>GrantThrive Platform</p>
                    '''
                )
        
        # Public announcement if enabled and published
        if auto_publish and grant.notification_settings.get('publicAnnouncement', False):
            # Here you would integrate with website/social media APIs
            pass
        
        status_message = 'Grant published successfully' if auto_publish else 'Grant submitted for review'
        
        return jsonify({
            'success': True,
            'message': status_message,
            'grant_id': grant.id,
            'status': grant.status
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@grant_wizard_bp.route('/api/grant-wizard/validate-step', methods=['POST'])
@jwt_required()
def validate_step():
    """Validate a specific step of the grant creation wizard"""
    try:
        data = request.get_json()
        step = data.get('step')
        form_data = data.get('formData', {})
        
        errors = {}
        
        if step == 1:
            if not form_data.get('title'):
                errors['title'] = 'Grant title is required'
            if not form_data.get('category'):
                errors['category'] = 'Category is required'
            if not form_data.get('description'):
                errors['description'] = 'Description is required'
            if not form_data.get('eligibilityCriteria'):
                errors['eligibilityCriteria'] = 'Eligibility criteria is required'
                
        elif step == 2:
            if not form_data.get('totalFunding'):
                errors['totalFunding'] = 'Total funding is required'
            if not form_data.get('applicationOpenDate'):
                errors['applicationOpenDate'] = 'Application open date is required'
            if not form_data.get('applicationCloseDate'):
                errors['applicationCloseDate'] = 'Application close date is required'
            
            # Validate date logic
            if form_data.get('applicationOpenDate') and form_data.get('applicationCloseDate'):
                open_date = datetime.fromisoformat(form_data.get('applicationOpenDate'))
                close_date = datetime.fromisoformat(form_data.get('applicationCloseDate'))
                
                if close_date <= open_date:
                    errors['applicationCloseDate'] = 'Close date must be after open date'
                
                if open_date < datetime.now().date():
                    errors['applicationOpenDate'] = 'Open date cannot be in the past'
                    
        elif step == 3:
            # Application form validation
            custom_questions = form_data.get('customQuestions', [])
            for i, question in enumerate(custom_questions):
                if not question.get('question'):
                    errors[f'customQuestion_{i}'] = 'Question text is required'
                    
        elif step == 4:
            review_committee = form_data.get('reviewCommittee', [])
            if len(review_committee) == 0:
                errors['reviewCommittee'] = 'At least one reviewer is required'
            
            for i, reviewer in enumerate(review_committee):
                if not reviewer.get('name'):
                    errors[f'reviewer_{i}_name'] = 'Reviewer name is required'
                if not reviewer.get('email'):
                    errors[f'reviewer_{i}_email'] = 'Reviewer email is required'
        
        return jsonify({
            'success': True,
            'valid': len(errors) == 0,
            'errors': errors
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@grant_wizard_bp.route('/api/grant-wizard/ai-suggestions', methods=['POST'])
@jwt_required()
def get_ai_suggestions():
    """Get AI-powered suggestions for grant creation"""
    try:
        data = request.get_json()
        step = data.get('step')
        form_data = data.get('formData', {})
        
        suggestions = []
        
        if step == 1:
            category = form_data.get('category')
            if category == 'Community Development':
                suggestions = [
                    'Consider adding community impact criteria',
                    'Include sustainability requirements',
                    'Add partnership opportunities with local organizations',
                    'Consider requiring community consultation evidence'
                ]
            elif category == 'Youth Programs':
                suggestions = [
                    'Include age-specific eligibility criteria',
                    'Consider safety and supervision requirements',
                    'Add youth engagement metrics',
                    'Include mentor/volunteer requirements'
                ]
            elif category == 'Environmental Sustainability':
                suggestions = [
                    'Require environmental impact assessment',
                    'Include carbon footprint reduction goals',
                    'Consider long-term sustainability plans',
                    'Add community education components'
                ]
            else:
                suggestions = [
                    'Consider adding community impact criteria',
                    'Suggested funding range: $5,000-$50,000',
                    'Include sustainability requirements',
                    'Add partnership opportunities'
                ]
                
        elif step == 2:
            total_funding = form_data.get('totalFunding')
            if total_funding:
                funding_amount = float(total_funding)
                if funding_amount < 10000:
                    suggestions.append('Consider shorter assessment period for smaller grants')
                elif funding_amount > 100000:
                    suggestions.append('Recommend longer assessment period for large grants')
                    
            suggestions.extend([
                'Allow 4-6 weeks for assessment',
                'Consider quarterly funding cycles',
                'Set realistic project timelines',
                'Include milestone reporting dates'
            ])
            
        elif step == 3:
            suggestions = [
                'Add project sustainability questions',
                'Include community engagement metrics',
                'Consider partnership requirements',
                'Add innovation criteria',
                'Include risk management questions'
            ]
            
        elif step == 4:
            suggestions = [
                'Assign diverse review committee',
                'Set clear scoring criteria',
                'Plan public announcement',
                'Schedule information sessions',
                'Consider community representative on committee'
            ]
        
        return jsonify({
            'success': True,
            'suggestions': suggestions
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@grant_wizard_bp.route('/api/grant-wizard/preview', methods=['POST'])
@jwt_required()
def preview_grant():
    """Generate preview of grant program"""
    try:
        data = request.get_json()
        form_data = data.get('formData', {})
        
        # Generate preview HTML/data
        preview_data = {
            'title': form_data.get('title', 'Untitled Grant'),
            'category': form_data.get('category', ''),
            'description': form_data.get('description', ''),
            'eligibility_criteria': form_data.get('eligibilityCriteria', ''),
            'funding_info': {
                'total_funding': form_data.get('totalFunding'),
                'max_amount': form_data.get('maxApplicationAmount'),
                'min_amount': form_data.get('minApplicationAmount')
            },
            'dates': {
                'open_date': form_data.get('applicationOpenDate'),
                'close_date': form_data.get('applicationCloseDate'),
                'funding_start': form_data.get('fundingStartDate'),
                'funding_end': form_data.get('fundingEndDate')
            },
            'required_documents': form_data.get('requiredDocuments', []),
            'custom_questions': form_data.get('customQuestions', []),
            'application_requirements': {
                'budget_breakdown': form_data.get('budgetRequirements', True),
                'project_timeline': form_data.get('projectTimeline', True),
                'impact_measurement': form_data.get('impactMeasurement', True),
                'partnership_details': form_data.get('partnershipDetails', False)
            }
        }
        
        return jsonify({
            'success': True,
            'preview': preview_data
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

