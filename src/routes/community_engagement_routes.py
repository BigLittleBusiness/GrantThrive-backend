"""
Community Engagement Routes for GrantThrive
API endpoints for community voting and grant mapping functionality
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..services.community_voting_service import CommunityVotingService
from ..services.grant_mapping_service import GrantMappingService
from ..utils.database import get_db_session

# Create blueprint
community_engagement_bp = Blueprint('community_engagement', __name__, url_prefix='/api/community')

# Community Voting Endpoints

@community_engagement_bp.route('/voting/campaigns', methods=['POST'])
@jwt_required()
def create_voting_campaign():
    """Create a new community voting campaign"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'start_date', 'end_date', 'council_id']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'error': f'Missing required field: {field}'}), 400
        
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.create_voting_campaign(
            council_id=data['council_id'],
            campaign_data=data,
            created_by=current_user
        )
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/voting/campaigns/<int:campaign_id>/options', methods=['POST'])
@jwt_required()
def add_voting_options(campaign_id):
    """Add voting options to a campaign"""
    try:
        data = request.get_json()
        
        if 'options' not in data or not isinstance(data['options'], list):
            return jsonify({'success': False, 'error': 'Options array is required'}), 400
        
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.add_voting_options(campaign_id, data['options'])
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/voting/campaigns/<int:campaign_id>/vote', methods=['POST'])
def submit_vote(campaign_id):
    """Submit a vote in a campaign (public endpoint)"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'option_id' not in data:
            return jsonify({'success': False, 'error': 'Option ID is required'}), 400
        
        # Get voter information from request
        voter_data = {
            'email': data.get('email'),
            'phone': data.get('phone'),
            'postcode': data.get('postcode'),
            'age_group': data.get('age_group'),
            'ip_address': request.remote_addr,
            'is_verified': data.get('is_verified', False),
            'verification_method': data.get('verification_method', 'none')
        }
        
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.submit_vote(campaign_id, data['option_id'], voter_data)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/voting/campaigns/<int:campaign_id>/results', methods=['GET'])
def get_campaign_results(campaign_id):
    """Get voting results for a campaign (public endpoint)"""
    try:
        include_demographics = request.args.get('include_demographics', 'false').lower() == 'true'
        
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.get_campaign_results(campaign_id, include_demographics)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/voting/campaigns/public/<council_id>', methods=['GET'])
def get_public_campaigns(council_id):
    """Get active public voting campaigns for a council"""
    try:
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.get_public_campaigns(council_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/voting/options/<int:option_id>/comments', methods=['POST'])
def add_comment(option_id):
    """Add a comment to a voting option (public endpoint)"""
    try:
        data = request.get_json()
        
        if 'comment_text' not in data:
            return jsonify({'success': False, 'error': 'Comment text is required'}), 400
        
        db_session = get_db_session()
        voting_service = CommunityVotingService(db_session)
        
        result = voting_service.add_comment(option_id, data)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Grant Mapping Endpoints

@community_engagement_bp.route('/mapping/grants/<grant_id>/location', methods=['POST'])
@jwt_required()
def add_grant_location(grant_id):
    """Add a location for a grant project"""
    try:
        data = request.get_json()
        
        if 'address' not in data:
            return jsonify({'success': False, 'error': 'Address is required'}), 400
        
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.add_grant_location(grant_id, data)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/grants/<grant_id>/updates', methods=['POST'])
@jwt_required()
def add_project_update(grant_id):
    """Add a project update with photos and progress"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        
        if 'title' not in data:
            return jsonify({'success': False, 'error': 'Update title is required'}), 400
        
        data['submitted_by'] = current_user
        
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.add_project_update(grant_id, data)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/public/<council_id>', methods=['GET'])
def get_public_grant_map(council_id):
    """Get public grant map data for a council"""
    try:
        # Get filter parameters
        filters = {}
        if request.args.get('postcode'):
            filters['postcode'] = request.args.get('postcode')
        if request.args.get('suburb'):
            filters['suburb'] = request.args.get('suburb')
        if request.args.get('project_status'):
            filters['project_status'] = request.args.get('project_status')
        
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.get_public_grant_map_data(council_id, filters)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/grants/<grant_id>/details', methods=['GET'])
def get_grant_project_details(grant_id):
    """Get detailed information about a grant project (public endpoint)"""
    try:
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.get_grant_project_details(grant_id)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 404
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/config/<council_id>', methods=['POST'])
@jwt_required()
def configure_council_map(council_id):
    """Configure map settings for a council"""
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        data['updated_by'] = current_user
        
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.configure_council_map(council_id, data)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/config/<council_id>', methods=['GET'])
def get_council_map_config(council_id):
    """Get map configuration for a council (public endpoint)"""
    try:
        from ..models.grant_mapping import MapConfiguration
        
        db_session = get_db_session()
        config = db_session.query(MapConfiguration).filter(
            MapConfiguration.council_id == council_id
        ).first()
        
        if not config:
            # Return default configuration
            default_config = {
                'council_id': council_id,
                'default_center': {'lat': -33.8688, 'lng': 151.2093},
                'default_zoom_level': 12,
                'map_style': 'standard',
                'marker_style': 'default',
                'is_public_map_enabled': True,
                'display_options': {
                    'show_grant_amounts': True,
                    'show_project_status': True,
                    'show_completion_dates': True
                }
            }
            return jsonify({'success': True, 'configuration': default_config}), 200
        
        mapping_service = GrantMappingService(db_session)
        config_data = mapping_service._serialize_map_config(config)
        
        return jsonify({'success': True, 'configuration': config_data}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@community_engagement_bp.route('/mapping/grants/<grant_id>/feedback', methods=['POST'])
def submit_community_feedback(grant_id):
    """Submit community feedback for a grant project (public endpoint)"""
    try:
        data = request.get_json()
        
        if 'feedback_text' not in data:
            return jsonify({'success': False, 'error': 'Feedback text is required'}), 400
        
        db_session = get_db_session()
        mapping_service = GrantMappingService(db_session)
        
        result = mapping_service.submit_community_feedback(grant_id, data)
        
        if result['success']:
            return jsonify(result), 201
        else:
            return jsonify(result), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Utility Endpoints

@community_engagement_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for community engagement features"""
    return jsonify({
        'success': True,
        'service': 'Community Engagement API',
        'features': [
            'Community Voting',
            'Grant Mapping',
            'Project Updates',
            'Community Feedback'
        ],
        'timestamp': '2024-08-31T12:00:00Z'
    }), 200

@community_engagement_bp.route('/stats/<council_id>', methods=['GET'])
def get_engagement_stats(council_id):
    """Get community engagement statistics for a council"""
    try:
        from ..models.community_voting import VotingCampaign, CommunityVote
        from ..models.grant_mapping import GrantLocation, ProjectUpdate, CommunityFeedback
        from sqlalchemy import func
        
        db_session = get_db_session()
        
        # Voting statistics
        total_campaigns = db_session.query(VotingCampaign).filter(
            VotingCampaign.council_id == council_id
        ).count()
        
        total_votes = db_session.query(CommunityVote).join(VotingCampaign).filter(
            VotingCampaign.council_id == council_id
        ).count()
        
        # Mapping statistics
        total_grant_locations = db_session.query(GrantLocation).filter(
            GrantLocation.is_public_visible == True
        ).count()
        
        total_project_updates = db_session.query(ProjectUpdate).filter(
            ProjectUpdate.is_public == True
        ).count()
        
        total_community_feedback = db_session.query(CommunityFeedback).filter(
            CommunityFeedback.is_approved == True
        ).count()
        
        stats = {
            'council_id': council_id,
            'voting': {
                'total_campaigns': total_campaigns,
                'total_votes': total_votes
            },
            'mapping': {
                'total_grant_locations': total_grant_locations,
                'total_project_updates': total_project_updates,
                'total_community_feedback': total_community_feedback
            },
            'last_updated': '2024-08-31T12:00:00Z'
        }
        
        return jsonify({'success': True, 'stats': stats}), 200
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

