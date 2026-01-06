"""
Smart Push Notification Service for GrantThrive Platform
Enables real-time browser push notifications for grant updates
"""

import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

class PushNotificationService:
    """
    Service for managing browser push notifications
    """
    
    def __init__(self):
        self.vapid_public_key = os.getenv('VAPID_PUBLIC_KEY', 'demo-public-key')
        self.vapid_private_key = os.getenv('VAPID_PRIVATE_KEY', 'demo-private-key')
        self.notification_types = self._get_notification_types()
        
    def _get_notification_types(self):
        """
        Define available notification types and their configurations
        """
        return {
            'application_submitted': {
                'title': '✅ Application Submitted',
                'icon': '/static/icons/success.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'application'
            },
            'application_approved': {
                'title': '🎉 Application Approved',
                'icon': '/static/icons/approved.png',
                'badge': '/static/icons/badge.png',
                'priority': 'high',
                'category': 'application'
            },
            'application_rejected': {
                'title': '❌ Application Update',
                'icon': '/static/icons/info.png',
                'badge': '/static/icons/badge.png',
                'priority': 'high',
                'category': 'application'
            },
            'deadline_reminder': {
                'title': '⏰ Deadline Reminder',
                'icon': '/static/icons/deadline.png',
                'badge': '/static/icons/badge.png',
                'priority': 'high',
                'category': 'deadline'
            },
            'new_grant_available': {
                'title': '🆕 New Grant Available',
                'icon': '/static/icons/grant.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'opportunity'
            },
            'document_required': {
                'title': '📄 Document Required',
                'icon': '/static/icons/document.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'action_required'
            },
            'meeting_reminder': {
                'title': '🤝 Meeting Reminder',
                'icon': '/static/icons/meeting.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'meeting'
            },
            'payment_processed': {
                'title': '💰 Payment Processed',
                'icon': '/static/icons/payment.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'financial'
            },
            'report_due': {
                'title': '📊 Report Due',
                'icon': '/static/icons/report.png',
                'badge': '/static/icons/badge.png',
                'priority': 'normal',
                'category': 'reporting'
            },
            'system_update': {
                'title': '🔄 System Update',
                'icon': '/static/icons/system.png',
                'badge': '/static/icons/badge.png',
                'priority': 'low',
                'category': 'system'
            }
        }
    
    def create_notification_payload(self, notification_type: str, data: Dict) -> Dict:
        """
        Create notification payload for specific type
        
        Args:
            notification_type (str): Type of notification
            data (dict): Notification data
            
        Returns:
            dict: Notification payload
        """
        try:
            if notification_type not in self.notification_types:
                raise ValueError(f"Unknown notification type: {notification_type}")
            
            config = self.notification_types[notification_type]
            
            # Base payload
            payload = {
                'title': config['title'],
                'body': self._generate_notification_body(notification_type, data),
                'icon': config['icon'],
                'badge': config['badge'],
                'tag': f"{notification_type}_{data.get('id', 'default')}",
                'requireInteraction': config['priority'] == 'high',
                'silent': config['priority'] == 'low',
                'timestamp': int(datetime.now().timestamp() * 1000),
                'data': {
                    'type': notification_type,
                    'category': config['category'],
                    'priority': config['priority'],
                    'url': self._generate_notification_url(notification_type, data),
                    'actions': self._generate_notification_actions(notification_type, data),
                    **data
                }
            }
            
            # Add notification actions
            if config['priority'] in ['high', 'normal']:
                payload['actions'] = self._generate_notification_actions(notification_type, data)
            
            return payload
            
        except Exception as e:
            return {
                'title': 'GrantThrive Notification',
                'body': 'You have a new update',
                'icon': '/static/icons/default.png',
                'data': {'error': str(e)}
            }
    
    def _generate_notification_body(self, notification_type: str, data: Dict) -> str:
        """
        Generate notification body text based on type and data
        """
        templates = {
            'application_submitted': "Your application for '{grant_title}' has been successfully submitted.",
            'application_approved': "Congratulations! Your application for '{grant_title}' has been approved for ${amount:,.0f}.",
            'application_rejected': "Your application for '{grant_title}' requires attention. Please review the feedback.",
            'deadline_reminder': "Grant '{grant_title}' deadline is {time_remaining}. Don't miss out!",
            'new_grant_available': "New grant '{grant_title}' is now available. Funding up to ${amount:,.0f}.",
            'document_required': "Additional documents required for '{grant_title}'. Please upload by {due_date}.",
            'meeting_reminder': "Meeting '{meeting_title}' starts in {time_until}.",
            'payment_processed': "Payment of ${amount:,.0f} for '{grant_title}' has been processed.",
            'report_due': "Progress report for '{grant_title}' is due {due_date}.",
            'system_update': "GrantThrive has been updated with new features and improvements."
        }
        
        template = templates.get(notification_type, "You have a new update from GrantThrive.")
        
        try:
            return template.format(**data)
        except (KeyError, ValueError):
            return template
    
    def _generate_notification_url(self, notification_type: str, data: Dict) -> str:
        """
        Generate URL for notification click action
        """
        base_url = "https://grantthrive.com"
        
        url_patterns = {
            'application_submitted': f"{base_url}/applications/{data.get('application_id', '')}",
            'application_approved': f"{base_url}/applications/{data.get('application_id', '')}",
            'application_rejected': f"{base_url}/applications/{data.get('application_id', '')}",
            'deadline_reminder': f"{base_url}/grants/{data.get('grant_id', '')}",
            'new_grant_available': f"{base_url}/grants/{data.get('grant_id', '')}",
            'document_required': f"{base_url}/applications/{data.get('application_id', '')}/documents",
            'meeting_reminder': f"{base_url}/meetings/{data.get('meeting_id', '')}",
            'payment_processed': f"{base_url}/payments/{data.get('payment_id', '')}",
            'report_due': f"{base_url}/reports/{data.get('report_id', '')}",
            'system_update': f"{base_url}/updates"
        }
        
        return url_patterns.get(notification_type, base_url)
    
    def _generate_notification_actions(self, notification_type: str, data: Dict) -> List[Dict]:
        """
        Generate notification action buttons
        """
        action_sets = {
            'application_submitted': [
                {'action': 'view', 'title': 'View Application', 'icon': '/static/icons/view.png'},
                {'action': 'track', 'title': 'Track Progress', 'icon': '/static/icons/track.png'}
            ],
            'application_approved': [
                {'action': 'view', 'title': 'View Details', 'icon': '/static/icons/view.png'},
                {'action': 'next_steps', 'title': 'Next Steps', 'icon': '/static/icons/next.png'}
            ],
            'application_rejected': [
                {'action': 'view_feedback', 'title': 'View Feedback', 'icon': '/static/icons/feedback.png'},
                {'action': 'reapply', 'title': 'Reapply', 'icon': '/static/icons/reapply.png'}
            ],
            'deadline_reminder': [
                {'action': 'apply_now', 'title': 'Apply Now', 'icon': '/static/icons/apply.png'},
                {'action': 'set_reminder', 'title': 'Set Reminder', 'icon': '/static/icons/reminder.png'}
            ],
            'new_grant_available': [
                {'action': 'view_grant', 'title': 'View Grant', 'icon': '/static/icons/view.png'},
                {'action': 'apply', 'title': 'Apply Now', 'icon': '/static/icons/apply.png'}
            ],
            'document_required': [
                {'action': 'upload', 'title': 'Upload Now', 'icon': '/static/icons/upload.png'},
                {'action': 'view_requirements', 'title': 'View Requirements', 'icon': '/static/icons/requirements.png'}
            ],
            'meeting_reminder': [
                {'action': 'join', 'title': 'Join Meeting', 'icon': '/static/icons/join.png'},
                {'action': 'reschedule', 'title': 'Reschedule', 'icon': '/static/icons/reschedule.png'}
            ],
            'payment_processed': [
                {'action': 'view_receipt', 'title': 'View Receipt', 'icon': '/static/icons/receipt.png'},
                {'action': 'download', 'title': 'Download', 'icon': '/static/icons/download.png'}
            ],
            'report_due': [
                {'action': 'submit_report', 'title': 'Submit Report', 'icon': '/static/icons/submit.png'},
                {'action': 'request_extension', 'title': 'Request Extension', 'icon': '/static/icons/extension.png'}
            ]
        }
        
        return action_sets.get(notification_type, [
            {'action': 'view', 'title': 'View', 'icon': '/static/icons/view.png'}
        ])
    
    def schedule_notification(self, user_id: str, notification_type: str, data: Dict, 
                            send_time: Optional[datetime] = None) -> Dict:
        """
        Schedule a notification to be sent
        
        Args:
            user_id (str): User identifier
            notification_type (str): Type of notification
            data (dict): Notification data
            send_time (datetime, optional): When to send (default: now)
            
        Returns:
            dict: Scheduled notification info
        """
        try:
            if not send_time:
                send_time = datetime.now()
            
            payload = self.create_notification_payload(notification_type, data)
            
            # In production, this would store in database and use a job queue
            notification_record = {
                'id': f"notif_{int(datetime.now().timestamp())}_{user_id}",
                'user_id': user_id,
                'type': notification_type,
                'payload': payload,
                'scheduled_time': send_time.isoformat(),
                'status': 'scheduled',
                'created_at': datetime.now().isoformat()
            }
            
            return {
                'success': True,
                'notification_id': notification_record['id'],
                'scheduled_time': send_time.isoformat(),
                'payload': payload
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def send_immediate_notification(self, user_id: str, notification_type: str, data: Dict) -> Dict:
        """
        Send notification immediately
        
        Args:
            user_id (str): User identifier
            notification_type (str): Type of notification
            data (dict): Notification data
            
        Returns:
            dict: Send result
        """
        try:
            payload = self.create_notification_payload(notification_type, data)
            
            # In production, this would use Web Push Protocol
            # For now, we'll simulate the send
            result = {
                'success': True,
                'notification_id': f"notif_{int(datetime.now().timestamp())}_{user_id}",
                'user_id': user_id,
                'payload': payload,
                'sent_at': datetime.now().isoformat(),
                'delivery_status': 'delivered'
            }
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_deadline_reminder_series(self, grant_data: Dict, user_id: str) -> List[Dict]:
        """
        Create series of deadline reminder notifications
        
        Args:
            grant_data (dict): Grant information
            user_id (str): User identifier
            
        Returns:
            list: Scheduled notifications
        """
        try:
            deadline = grant_data.get('deadline')
            if isinstance(deadline, str):
                deadline_dt = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
            else:
                deadline_dt = deadline
            
            notifications = []
            
            # Reminder schedule
            reminder_schedule = [
                {'days_before': 7, 'time_remaining': 'in 1 week'},
                {'days_before': 3, 'time_remaining': 'in 3 days'},
                {'days_before': 1, 'time_remaining': 'tomorrow'},
                {'hours_before': 2, 'time_remaining': 'in 2 hours'}
            ]
            
            for reminder in reminder_schedule:
                if 'days_before' in reminder:
                    send_time = deadline_dt - timedelta(days=reminder['days_before'])
                else:
                    send_time = deadline_dt - timedelta(hours=reminder['hours_before'])
                
                # Only schedule future reminders
                if send_time > datetime.now():
                    notification_data = {
                        'grant_id': grant_data.get('grant_id'),
                        'grant_title': grant_data.get('title'),
                        'time_remaining': reminder['time_remaining'],
                        'deadline': deadline_dt.strftime('%B %d, %Y at %I:%M %p')
                    }
                    
                    result = self.schedule_notification(
                        user_id, 
                        'deadline_reminder', 
                        notification_data, 
                        send_time
                    )
                    
                    if result['success']:
                        notifications.append(result)
            
            return notifications
            
        except Exception as e:
            return [{'success': False, 'error': str(e)}]
    
    def get_user_notification_preferences(self, user_id: str) -> Dict:
        """
        Get user notification preferences
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: User notification preferences
        """
        # Default preferences - in production, load from database
        return {
            'push_notifications_enabled': True,
            'notification_types': {
                'application_updates': True,
                'deadline_reminders': True,
                'new_grants': True,
                'meetings': True,
                'payments': True,
                'reports': True,
                'system_updates': False
            },
            'quiet_hours': {
                'enabled': True,
                'start_time': '22:00',
                'end_time': '08:00',
                'timezone': 'Australia/Sydney'
            },
            'delivery_preferences': {
                'high_priority': 'immediate',
                'normal_priority': 'immediate',
                'low_priority': 'batched'
            }
        }
    
    def update_user_notification_preferences(self, user_id: str, preferences: Dict) -> Dict:
        """
        Update user notification preferences
        
        Args:
            user_id (str): User identifier
            preferences (dict): New preferences
            
        Returns:
            dict: Update result
        """
        try:
            # In production, save to database
            return {
                'success': True,
                'user_id': user_id,
                'preferences': preferences,
                'updated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_notification_statistics(self, user_id: str) -> Dict:
        """
        Get notification statistics for user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: Notification statistics
        """
        # Mock statistics - in production, query from database
        return {
            'total_sent': 45,
            'total_delivered': 43,
            'total_clicked': 28,
            'delivery_rate': 95.6,
            'click_rate': 62.2,
            'by_type': {
                'deadline_reminders': {'sent': 12, 'clicked': 10},
                'application_updates': {'sent': 8, 'clicked': 7},
                'new_grants': {'sent': 15, 'clicked': 8},
                'meetings': {'sent': 5, 'clicked': 2},
                'payments': {'sent': 3, 'clicked': 1},
                'reports': {'sent': 2, 'clicked': 0}
            },
            'recent_activity': [
                {
                    'type': 'deadline_reminder',
                    'sent_at': '2024-08-29T10:30:00Z',
                    'status': 'clicked'
                },
                {
                    'type': 'new_grant_available',
                    'sent_at': '2024-08-28T14:15:00Z',
                    'status': 'delivered'
                }
            ]
        }
    
    def get_vapid_public_key(self) -> str:
        """
        Get VAPID public key for client-side subscription
        
        Returns:
            str: VAPID public key
        """
        return self.vapid_public_key

