"""
Quick Wins API Routes for GrantThrive Platform
Handles calendar integration, push notifications, pre-fill, and progress tracking
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import json

from ..services.calendar_service import CalendarService
from ..services.push_notification_service import PushNotificationService
from ..services.application_prefill_service import ApplicationPrefillService
from ..services.progress_tracking_service import ProgressTrackingService

# Initialize services
calendar_service = CalendarService()
push_service = PushNotificationService()
prefill_service = ApplicationPrefillService()
progress_service = ProgressTrackingService()

# Create blueprint
quick_wins_bp = Blueprint('quick_wins', __name__, url_prefix='/api/quick-wins')

# ============================================================================
# CALENDAR INTEGRATION ROUTES
# ============================================================================

@quick_wins_bp.route('/calendar/generate-link', methods=['POST'])
def generate_calendar_link():
    """Generate calendar link for grant deadline"""
    try:
        data = request.get_json()
        
        result = calendar_service.generate_calendar_link(
            grant_data=data.get('grant_data', {}),
            calendar_type=data.get('calendar_type', 'google'),
            reminder_settings=data.get('reminder_settings', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/calendar/bulk-generate', methods=['POST'])
def bulk_generate_calendar_links():
    """Generate calendar links for multiple grants"""
    try:
        data = request.get_json()
        
        result = calendar_service.bulk_generate_calendar_links(
            grants_data=data.get('grants_data', []),
            calendar_type=data.get('calendar_type', 'google'),
            reminder_settings=data.get('reminder_settings', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/calendar/reminder-series', methods=['POST'])
def create_reminder_series():
    """Create series of calendar reminders"""
    try:
        data = request.get_json()
        
        result = calendar_service.create_reminder_series(
            grant_data=data.get('grant_data', {}),
            reminder_schedule=data.get('reminder_schedule', []),
            calendar_type=data.get('calendar_type', 'google')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# PUSH NOTIFICATION ROUTES
# ============================================================================

@quick_wins_bp.route('/notifications/vapid-key', methods=['GET'])
def get_vapid_public_key():
    """Get VAPID public key for push notification subscription"""
    try:
        public_key = push_service.get_vapid_public_key()
        
        return jsonify({
            'success': True,
            'vapid_public_key': public_key
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/send', methods=['POST'])
def send_push_notification():
    """Send immediate push notification"""
    try:
        data = request.get_json()
        
        result = push_service.send_immediate_notification(
            user_id=data.get('user_id'),
            notification_type=data.get('notification_type'),
            data=data.get('notification_data', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/schedule', methods=['POST'])
def schedule_push_notification():
    """Schedule push notification"""
    try:
        data = request.get_json()
        
        send_time = None
        if data.get('send_time'):
            send_time = datetime.fromisoformat(data['send_time'])
        
        result = push_service.schedule_notification(
            user_id=data.get('user_id'),
            notification_type=data.get('notification_type'),
            data=data.get('notification_data', {}),
            send_time=send_time
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/deadline-series', methods=['POST'])
def create_deadline_notification_series():
    """Create series of deadline reminder notifications"""
    try:
        data = request.get_json()
        
        result = push_service.create_deadline_reminder_series(
            grant_data=data.get('grant_data', {}),
            user_id=data.get('user_id')
        )
        
        return jsonify({
            'success': True,
            'notifications': result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/preferences/<user_id>', methods=['GET'])
def get_notification_preferences(user_id):
    """Get user notification preferences"""
    try:
        preferences = push_service.get_user_notification_preferences(user_id)
        
        return jsonify({
            'success': True,
            'preferences': preferences
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/preferences/<user_id>', methods=['PUT'])
def update_notification_preferences(user_id):
    """Update user notification preferences"""
    try:
        data = request.get_json()
        
        result = push_service.update_user_notification_preferences(
            user_id=user_id,
            preferences=data.get('preferences', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/notifications/statistics/<user_id>', methods=['GET'])
def get_notification_statistics(user_id):
    """Get notification statistics for user"""
    try:
        stats = push_service.get_notification_statistics(user_id)
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# APPLICATION PRE-FILL ROUTES
# ============================================================================

@quick_wins_bp.route('/prefill/profile/<user_id>', methods=['POST'])
def create_organization_profile(user_id):
    """Create organization profile for pre-fill"""
    try:
        data = request.get_json()
        
        result = prefill_service.create_organization_profile(
            user_id=user_id,
            organization_data=data.get('organization_data', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/profile/<user_id>', methods=['GET'])
def get_organization_profile(user_id):
    """Get organization profile"""
    try:
        profile = prefill_service.get_organization_profile(user_id)
        
        if profile:
            return jsonify({
                'success': True,
                'profile': profile
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Profile not found'
            }), 404
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/profile/<user_id>', methods=['PUT'])
def update_organization_profile(user_id):
    """Update organization profile"""
    try:
        data = request.get_json()
        
        result = prefill_service.update_organization_profile(
            user_id=user_id,
            updates=data.get('updates', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/suggestions/<user_id>', methods=['GET'])
def get_prefill_suggestions(user_id):
    """Get pre-fill suggestions for new application"""
    try:
        grant_type = request.args.get('grant_type')
        
        result = prefill_service.get_prefill_suggestions(
            user_id=user_id,
            grant_type=grant_type
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/apply/<user_id>', methods=['POST'])
def apply_prefill_data(user_id):
    """Apply pre-fill data to application form"""
    try:
        data = request.get_json()
        
        result = prefill_service.apply_prefill_data(
            user_id=user_id,
            application_form=data.get('application_form', {}),
            prefill_options=data.get('prefill_options', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/save-application/<user_id>', methods=['POST'])
def save_application_data(user_id):
    """Save application data for future pre-fill"""
    try:
        data = request.get_json()
        
        result = prefill_service.save_application_data(
            user_id=user_id,
            application_data=data.get('application_data', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/statistics/<user_id>', methods=['GET'])
def get_prefill_statistics(user_id):
    """Get pre-fill usage statistics"""
    try:
        result = prefill_service.get_prefill_statistics(user_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/export/<user_id>', methods=['GET'])
def export_organization_profile(user_id):
    """Export organization profile"""
    try:
        result = prefill_service.export_organization_profile(user_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/prefill/import/<user_id>', methods=['POST'])
def import_organization_profile(user_id):
    """Import organization profile"""
    try:
        data = request.get_json()
        
        result = prefill_service.import_organization_profile(
            user_id=user_id,
            import_data=data.get('import_data', {})
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# PROGRESS TRACKING ROUTES
# ============================================================================

@quick_wins_bp.route('/progress/initialize', methods=['POST'])
def initialize_application_progress():
    """Initialize progress tracking for new application"""
    try:
        data = request.get_json()
        
        result = progress_service.initialize_application_progress(
            application_id=data.get('application_id'),
            grant_type=data.get('grant_type', 'standard_grant'),
            custom_stages=data.get('custom_stages')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>', methods=['GET'])
def get_application_progress(application_id):
    """Get current progress for application"""
    try:
        result = progress_service.get_application_progress(application_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/summary', methods=['GET'])
def get_progress_summary(application_id):
    """Get condensed progress summary"""
    try:
        result = progress_service.get_progress_summary(application_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/update-field', methods=['POST'])
def update_field_progress(application_id):
    """Update progress when a field is completed"""
    try:
        data = request.get_json()
        
        result = progress_service.update_field_progress(
            application_id=application_id,
            field_name=data.get('field_name'),
            field_value=data.get('field_value')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/advance', methods=['POST'])
def advance_to_next_stage(application_id):
    """Advance application to next stage"""
    try:
        data = request.get_json()
        
        result = progress_service.advance_to_next_stage(
            application_id=application_id,
            force=data.get('force', False)
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/status', methods=['PUT'])
def update_application_status(application_id):
    """Update application status"""
    try:
        data = request.get_json()
        
        result = progress_service.update_application_status(
            application_id=application_id,
            new_status=data.get('new_status'),
            notes=data.get('notes')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/notes', methods=['POST'])
def add_progress_note(application_id):
    """Add note to current progress stage"""
    try:
        data = request.get_json()
        
        result = progress_service.add_progress_note(
            application_id=application_id,
            note=data.get('note'),
            note_type=data.get('note_type', 'general')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/blockers', methods=['POST'])
def add_progress_blocker(application_id):
    """Add blocker to current progress stage"""
    try:
        data = request.get_json()
        
        result = progress_service.add_progress_blocker(
            application_id=application_id,
            blocker=data.get('blocker'),
            severity=data.get('severity', 'medium')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/progress/<application_id>/blockers/<blocker_id>/resolve', methods=['POST'])
def resolve_progress_blocker(application_id, blocker_id):
    """Resolve a progress blocker"""
    try:
        data = request.get_json()
        
        result = progress_service.resolve_progress_blocker(
            application_id=application_id,
            blocker_id=blocker_id,
            resolution=data.get('resolution')
        )
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# COMBINED FEATURES ROUTES
# ============================================================================

@quick_wins_bp.route('/setup-application-automation', methods=['POST'])
def setup_application_automation():
    """Set up complete automation for new application"""
    try:
        data = request.get_json()
        
        application_id = data.get('application_id')
        user_id = data.get('user_id')
        grant_data = data.get('grant_data', {})
        
        results = {
            'application_id': application_id,
            'automation_setup': {}
        }
        
        # Initialize progress tracking
        if data.get('enable_progress_tracking', True):
            progress_result = progress_service.initialize_application_progress(
                application_id=application_id,
                grant_type=grant_data.get('grant_type', 'standard_grant')
            )
            results['automation_setup']['progress_tracking'] = progress_result
        
        # Set up deadline notifications
        if data.get('enable_deadline_notifications', True):
            notification_result = push_service.create_deadline_reminder_series(
                grant_data=grant_data,
                user_id=user_id
            )
            results['automation_setup']['deadline_notifications'] = {
                'success': True,
                'notifications': notification_result
            }
        
        # Generate calendar links
        if data.get('enable_calendar_integration', True):
            calendar_result = calendar_service.create_reminder_series(
                grant_data=grant_data,
                reminder_schedule=data.get('reminder_schedule', []),
                calendar_type=data.get('calendar_type', 'google')
            )
            results['automation_setup']['calendar_integration'] = calendar_result
        
        # Apply pre-fill if requested
        if data.get('enable_prefill', True) and data.get('application_form'):
            prefill_result = prefill_service.apply_prefill_data(
                user_id=user_id,
                application_form=data['application_form'],
                prefill_options=data.get('prefill_options', {})
            )
            results['automation_setup']['prefill'] = prefill_result
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@quick_wins_bp.route('/dashboard-summary/<user_id>', methods=['GET'])
def get_user_dashboard_summary(user_id):
    """Get comprehensive dashboard summary for user"""
    try:
        # Get user's applications (mock data for demo)
        user_applications = [
            'app_001', 'app_002', 'app_003'  # In production, query from database
        ]
        
        summary = {
            'user_id': user_id,
            'applications': [],
            'notifications': {},
            'prefill_stats': {},
            'calendar_events': []
        }
        
        # Get progress for each application
        for app_id in user_applications:
            progress_result = progress_service.get_progress_summary(app_id)
            if progress_result['success']:
                summary['applications'].append(progress_result['summary'])
        
        # Get notification statistics
        notification_stats = push_service.get_notification_statistics(user_id)
        summary['notifications'] = notification_stats
        
        # Get pre-fill statistics
        prefill_stats_result = prefill_service.get_prefill_statistics(user_id)
        if prefill_stats_result['success']:
            summary['prefill_stats'] = prefill_stats_result['statistics']
        
        # Get upcoming calendar events (mock data)
        summary['calendar_events'] = [
            {
                'title': 'Community Grant Deadline',
                'date': '2024-09-15',
                'type': 'deadline'
            },
            {
                'title': 'Grant Application Review Meeting',
                'date': '2024-09-10',
                'type': 'meeting'
            }
        ]
        
        return jsonify({
            'success': True,
            'summary': summary
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

