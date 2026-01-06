"""
Communication Preferences API Routes for GrantThrive Platform
Allows council admins to configure SMS vs Email communication preferences
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
from ..services.notification_service import NotificationService
from ..models.communication_preferences import NotificationEvent, CommunicationType

communication_bp = Blueprint('communication_bp', __name__)

# Initialize notification service
notification_service = NotificationService()

@communication_bp.route('/communication/preferences/<council_id>', methods=['GET'])
def get_communication_preferences(council_id):
    """
    Get communication preferences for a council
    """
    try:
        prefs = notification_service.get_council_preferences(council_id)
        return jsonify({
            "status": "success",
            "data": prefs.get_preferences_summary()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving preferences: {str(e)}"
        }), 500

@communication_bp.route('/communication/preferences/<council_id>', methods=['PUT'])
def update_communication_preferences(council_id):
    """
    Update communication preferences for a council
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "No preferences data provided"
            }), 400
        
        success, message = notification_service.update_council_preferences(council_id, data)
        
        if success:
            # Return updated preferences
            prefs = notification_service.get_council_preferences(council_id)
            return jsonify({
                "status": "success",
                "message": message,
                "data": prefs.get_preferences_summary()
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": message
            }), 400
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error updating preferences: {str(e)}"
        }), 500

@communication_bp.route('/communication/preferences/<council_id>/reset', methods=['POST'])
def reset_communication_preferences(council_id):
    """
    Reset communication preferences to defaults
    """
    try:
        prefs = notification_service.get_council_preferences(council_id)
        prefs.reset_to_defaults()
        
        return jsonify({
            "status": "success",
            "message": "Communication preferences reset to defaults",
            "data": prefs.get_preferences_summary()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error resetting preferences: {str(e)}"
        }), 500

@communication_bp.route('/communication/send-notification', methods=['POST'])
def send_notification():
    """
    Send a notification based on communication preferences
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['council_id', 'event_type']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }), 400
        
        success, result = notification_service.send_notification(data)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Notification sent successfully",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error sending notification: {str(e)}"
        }), 500

@communication_bp.route('/communication/send-bulk-notification', methods=['POST'])
def send_bulk_notification():
    """
    Send notifications to multiple recipients
    """
    try:
        data = request.get_json()
        
        if not data or 'recipients' not in data:
            return jsonify({
                "status": "error",
                "message": "Recipients list is required"
            }), 400
        
        success, result = notification_service.send_bulk_notification(data)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "Bulk notifications processed",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error sending bulk notifications: {str(e)}"
        }), 500

@communication_bp.route('/communication/history/<council_id>', methods=['GET'])
def get_notification_history(council_id):
    """
    Get notification history for a council
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        history = notification_service.get_notification_history(council_id, limit)
        
        return jsonify({
            "status": "success",
            "data": {
                "council_id": council_id,
                "total_records": len(history),
                "notifications": history
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving notification history: {str(e)}"
        }), 500

@communication_bp.route('/communication/statistics/<council_id>', methods=['GET'])
def get_notification_statistics(council_id):
    """
    Get notification statistics for a council
    """
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        stats = notification_service.get_notification_statistics(
            council_id, start_date, end_date
        )
        
        return jsonify({
            "status": "success",
            "data": {
                "council_id": council_id,
                "date_range": {
                    "start_date": start_date,
                    "end_date": end_date
                },
                "statistics": stats
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving statistics: {str(e)}"
        }), 500

@communication_bp.route('/communication/test-notification', methods=['POST'])
def test_notification():
    """
    Send a test notification to verify configuration
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['council_id', 'test_type']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }), 400
        
        council_id = data['council_id']
        test_type = data['test_type']  # 'email', 'sms', or 'both'
        
        # Create test notification data
        test_notification = {
            'council_id': council_id,
            'event_type': 'general_update',
            'email_address': data.get('test_email'),
            'phone_number': data.get('test_phone'),
            'custom_message': 'This is a test notification from GrantThrive. Your communication settings are working correctly!',
            'grant_data': {
                'grant_title': 'Test Grant Program',
                'grant_id': 'TEST-001',
                'organization_name': 'Test Organization'
            }
        }
        
        # Override preferences for test
        prefs = notification_service.get_council_preferences(council_id)
        original_pref = prefs.get_communication_preference(NotificationEvent.GENERAL_UPDATE)
        
        # Set test preference
        if test_type == 'email':
            test_pref = CommunicationType.EMAIL
        elif test_type == 'sms':
            test_pref = CommunicationType.SMS
        else:  # both
            test_pref = CommunicationType.BOTH
        
        prefs.set_communication_preference(NotificationEvent.GENERAL_UPDATE, test_pref)
        
        try:
            # Send test notification
            success, result = notification_service.send_notification(test_notification)
            
            # Restore original preference
            prefs.set_communication_preference(NotificationEvent.GENERAL_UPDATE, original_pref)
            
            if success:
                return jsonify({
                    "status": "success",
                    "message": "Test notification sent successfully",
                    "data": result
                }), 200
            else:
                return jsonify({
                    "status": "error",
                    "message": f"Test notification failed: {result}"
                }), 500
                
        except Exception as e:
            # Restore original preference even if test fails
            prefs.set_communication_preference(NotificationEvent.GENERAL_UPDATE, original_pref)
            raise e
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error sending test notification: {str(e)}"
        }), 500

@communication_bp.route('/communication/event-types', methods=['GET'])
def get_event_types():
    """
    Get list of available notification event types
    """
    try:
        event_types = []
        for event in NotificationEvent:
            event_types.append({
                'value': event.value,
                'name': event.name,
                'display_name': event.value.replace('_', ' ').title()
            })
        
        return jsonify({
            "status": "success",
            "data": {
                "event_types": event_types
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving event types: {str(e)}"
        }), 500

@communication_bp.route('/communication/communication-types', methods=['GET'])
def get_communication_types():
    """
    Get list of available communication types
    """
    try:
        communication_types = []
        for comm_type in CommunicationType:
            communication_types.append({
                'value': comm_type.value,
                'name': comm_type.name,
                'display_name': comm_type.value.replace('_', ' ').title()
            })
        
        return jsonify({
            "status": "success",
            "data": {
                "communication_types": communication_types
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving communication types: {str(e)}"
        }), 500

@communication_bp.route('/communication/applicant-preferences/<council_id>/<applicant_id>', methods=['GET'])
def get_applicant_preferences(council_id, applicant_id):
    """
    Get communication preferences for a specific applicant
    """
    try:
        prefs = notification_service.get_applicant_preferences(applicant_id, council_id)
        
        return jsonify({
            "status": "success",
            "data": prefs.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving applicant preferences: {str(e)}"
        }), 500

@communication_bp.route('/communication/applicant-preferences/<council_id>/<applicant_id>', methods=['PUT'])
def update_applicant_preferences(council_id, applicant_id):
    """
    Update communication preferences for a specific applicant
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "No preferences data provided"
            }), 400
        
        prefs = notification_service.get_applicant_preferences(applicant_id, council_id)
        
        # Update preferences
        if 'preferred_communication' in data:
            try:
                comm_type = CommunicationType(data['preferred_communication'])
                prefs.preferred_communication = comm_type
            except ValueError:
                return jsonify({
                    "status": "error",
                    "message": "Invalid communication type"
                }), 400
        
        if 'phone_number' in data:
            prefs.phone_number = data['phone_number']
        
        if 'phone_verified' in data:
            prefs.phone_verified = data['phone_verified']
        
        if 'opted_out_sms' in data:
            prefs.opted_out_sms = data['opted_out_sms']
        
        if 'opted_out_email' in data:
            prefs.opted_out_email = data['opted_out_email']
        
        if 'opted_out_all' in data:
            prefs.opted_out_all = data['opted_out_all']
        
        prefs.updated_at = datetime.now()
        
        return jsonify({
            "status": "success",
            "message": "Applicant preferences updated successfully",
            "data": prefs.to_dict()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error updating applicant preferences: {str(e)}"
        }), 500

