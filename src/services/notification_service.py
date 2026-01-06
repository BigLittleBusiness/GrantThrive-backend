"""
Intelligent Notification Service for GrantThrive Platform
Handles both SMS and Email notifications based on admin-configured preferences
"""

import os
from datetime import datetime
from ..models.communication_preferences import (
    CommunicationPreferences, 
    ApplicantCommunicationPreferences,
    NotificationEvent,
    CommunicationType
)
from ..integrations.sms_api import SMSConnector
from ..utils.email import EmailService

class NotificationService:
    """
    Intelligent notification service that respects council admin communication preferences
    and handles both SMS and email delivery based on configuration
    """
    
    def __init__(self):
        self.email_service = EmailService()
        self.sms_service = None  # Will be initialized when needed
        
        # In-memory storage for demo (in production, use database)
        self.council_preferences = {}
        self.applicant_preferences = {}
        
        # Notification tracking
        self.notification_log = []
    
    def get_council_preferences(self, council_id):
        """
        Get communication preferences for a council
        
        Args:
            council_id (str): Council identifier
            
        Returns:
            CommunicationPreferences: Council communication preferences
        """
        if council_id not in self.council_preferences:
            # Create default preferences for new council
            self.council_preferences[council_id] = CommunicationPreferences(council_id)
        
        return self.council_preferences[council_id]
    
    def update_council_preferences(self, council_id, preferences_data):
        """
        Update communication preferences for a council
        
        Args:
            council_id (str): Council identifier
            preferences_data (dict): New preferences data
            
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            prefs = self.get_council_preferences(council_id)
            
            # Update global settings
            if 'global_settings' in preferences_data:
                prefs.update_global_settings(preferences_data['global_settings'])
            
            # Update event-specific preferences
            if 'event_preferences' in preferences_data:
                for event_str, comm_type_str in preferences_data['event_preferences'].items():
                    try:
                        event = NotificationEvent(event_str)
                        comm_type = CommunicationType(comm_type_str)
                        prefs.set_communication_preference(event, comm_type)
                    except ValueError as e:
                        return False, f"Invalid event or communication type: {e}"
            
            return True, "Communication preferences updated successfully"
            
        except Exception as e:
            return False, f"Error updating preferences: {str(e)}"
    
    def get_applicant_preferences(self, applicant_id, council_id):
        """
        Get communication preferences for an applicant
        
        Args:
            applicant_id (str): Applicant identifier
            council_id (str): Council identifier
            
        Returns:
            ApplicantCommunicationPreferences: Applicant communication preferences
        """
        key = f"{council_id}:{applicant_id}"
        if key not in self.applicant_preferences:
            self.applicant_preferences[key] = ApplicantCommunicationPreferences(applicant_id, council_id)
        
        return self.applicant_preferences[key]
    
    def send_notification(self, notification_data):
        """
        Send notification based on council and applicant preferences
        
        Args:
            notification_data (dict): Notification information
            
        Returns:
            tuple: (success: bool, delivery_summary: dict or error_message: str)
        """
        try:
            # Extract notification data
            council_id = notification_data.get('council_id')
            applicant_id = notification_data.get('applicant_id')
            event_type_str = notification_data.get('event_type')
            email_address = notification_data.get('email_address')
            phone_number = notification_data.get('phone_number')
            grant_data = notification_data.get('grant_data', {})
            custom_message = notification_data.get('custom_message')
            
            # Validate required data
            if not council_id or not event_type_str:
                return False, "Council ID and event type are required"
            
            try:
                event_type = NotificationEvent(event_type_str)
            except ValueError:
                return False, f"Invalid event type: {event_type_str}"
            
            # Get preferences
            council_prefs = self.get_council_preferences(council_id)
            
            # Determine effective communication preference
            if applicant_id and council_prefs.allow_applicant_preference_override:
                applicant_prefs = self.get_applicant_preferences(applicant_id, council_id)
                effective_preference = applicant_prefs.get_effective_preference(council_prefs, event_type)
            else:
                effective_preference = council_prefs.get_communication_preference(event_type)
            
            # Prepare delivery summary
            delivery_summary = {
                'council_id': council_id,
                'applicant_id': applicant_id,
                'event_type': event_type_str,
                'effective_preference': effective_preference.value,
                'email_sent': False,
                'sms_sent': False,
                'email_result': None,
                'sms_result': None,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send email if required
            if effective_preference in [CommunicationType.EMAIL, CommunicationType.BOTH]:
                if email_address:
                    email_success, email_result = self._send_email_notification(
                        email_address, event_type, grant_data, custom_message, council_prefs
                    )
                    delivery_summary['email_sent'] = email_success
                    delivery_summary['email_result'] = email_result
                else:
                    delivery_summary['email_result'] = "No email address provided"
            
            # Send SMS if required
            if effective_preference in [CommunicationType.SMS, CommunicationType.BOTH]:
                if phone_number and council_prefs.is_within_business_hours():
                    sms_success, sms_result = self._send_sms_notification(
                        phone_number, event_type, grant_data, custom_message, council_prefs
                    )
                    delivery_summary['sms_sent'] = sms_success
                    delivery_summary['sms_result'] = sms_result
                elif not phone_number:
                    delivery_summary['sms_result'] = "No phone number provided"
                else:
                    delivery_summary['sms_result'] = "Outside business hours - SMS not sent"
            
            # Log notification
            self.notification_log.append(delivery_summary)
            
            # Determine overall success
            if effective_preference == CommunicationType.EMAIL:
                success = delivery_summary['email_sent']
            elif effective_preference == CommunicationType.SMS:
                success = delivery_summary['sms_sent']
            elif effective_preference == CommunicationType.BOTH:
                success = delivery_summary['email_sent'] or delivery_summary['sms_sent']
            else:  # NONE
                success = True  # Successfully did nothing
                delivery_summary['result'] = "No communication required (preference: NONE)"
            
            return success, delivery_summary
            
        except Exception as e:
            return False, f"Notification service error: {str(e)}"
    
    def _send_email_notification(self, email_address, event_type, grant_data, custom_message, council_prefs):
        """
        Send email notification
        
        Args:
            email_address (str): Recipient email address
            event_type (NotificationEvent): Type of notification
            grant_data (dict): Grant information
            custom_message (str): Custom message (optional)
            council_prefs (CommunicationPreferences): Council preferences
            
        Returns:
            tuple: (success: bool, result: str)
        """
        try:
            # Generate email content
            if custom_message:
                subject, body = self._generate_custom_email(event_type, grant_data, custom_message)
            else:
                subject, body = self._generate_standard_email(event_type, grant_data)
            
            # Send email using email service
            success, result = self.email_service.send_email(
                to_email=email_address,
                subject=subject,
                body=body,
                is_html=True
            )
            
            return success, result
            
        except Exception as e:
            return False, f"Email sending error: {str(e)}"
    
    def _send_sms_notification(self, phone_number, event_type, grant_data, custom_message, council_prefs):
        """
        Send SMS notification
        
        Args:
            phone_number (str): Recipient phone number
            event_type (NotificationEvent): Type of notification
            grant_data (dict): Grant information
            custom_message (str): Custom message (optional)
            council_prefs (CommunicationPreferences): Council preferences
            
        Returns:
            tuple: (success: bool, result: str)
        """
        try:
            # Initialize SMS service if needed
            if not self.sms_service:
                self.sms_service = SMSConnector(provider=council_prefs.sms_provider)
            
            # Generate SMS content
            if custom_message:
                message = custom_message
            else:
                message = self._generate_standard_sms(event_type, grant_data)
            
            # Send SMS
            if custom_message:
                success, result = self.sms_service.send_sms(
                    to_number=phone_number,
                    message=message,
                    message_type=event_type.value
                )
            else:
                success, result = self.sms_service.send_grant_notification(
                    to_number=phone_number,
                    grant_data=grant_data,
                    notification_type=event_type.value
                )
            
            return success, result
            
        except Exception as e:
            return False, f"SMS sending error: {str(e)}"
    
    def _generate_standard_email(self, event_type, grant_data):
        """
        Generate standard email content for event type
        
        Args:
            event_type (NotificationEvent): Type of notification
            grant_data (dict): Grant information
            
        Returns:
            tuple: (subject: str, body: str)
        """
        grant_title = grant_data.get('grant_title', 'Grant Application')
        grant_id = grant_data.get('grant_id', 'N/A')
        organization = grant_data.get('organization_name', '')
        amount = grant_data.get('funding_amount', 0)
        
        email_templates = {
            NotificationEvent.APPLICATION_RECEIVED: {
                'subject': f'Grant Application Received - {grant_title}',
                'body': f'''
                <h2>Application Received Successfully</h2>
                <p>Dear {organization},</p>
                <p>We have successfully received your grant application:</p>
                <ul>
                    <li><strong>Grant:</strong> {grant_title}</li>
                    <li><strong>Application ID:</strong> {grant_id}</li>
                    <li><strong>Funding Requested:</strong> ${amount:,.2f}</li>
                </ul>
                <p>We will review your application and notify you of the outcome.</p>
                <p>Thank you for applying!</p>
                <p>Best regards,<br>GrantThrive Platform</p>
                '''
            },
            NotificationEvent.APPLICATION_APPROVED: {
                'subject': f'🎉 Grant Application APPROVED - {grant_title}',
                'body': f'''
                <h2 style="color: #28a745;">Congratulations! Your Grant Application Has Been Approved</h2>
                <p>Dear {organization},</p>
                <p>We are delighted to inform you that your grant application has been <strong>APPROVED</strong>:</p>
                <ul>
                    <li><strong>Grant:</strong> {grant_title}</li>
                    <li><strong>Application ID:</strong> {grant_id}</li>
                    <li><strong>Approved Amount:</strong> ${amount:,.2f}</li>
                </ul>
                <p>Please check your GrantThrive account for next steps and required documentation.</p>
                <p>Congratulations on this achievement!</p>
                <p>Best regards,<br>GrantThrive Platform</p>
                '''
            },
            NotificationEvent.APPLICATION_REJECTED: {
                'subject': f'Grant Application Update - {grant_title}',
                'body': f'''
                <h2>Grant Application Update</h2>
                <p>Dear {organization},</p>
                <p>Thank you for your interest in our grant program. Unfortunately, your application was not successful this time:</p>
                <ul>
                    <li><strong>Grant:</strong> {grant_title}</li>
                    <li><strong>Application ID:</strong> {grant_id}</li>
                </ul>
                <p>Please check your GrantThrive account for detailed feedback and information about future opportunities.</p>
                <p>We encourage you to apply for future grants that match your organization's goals.</p>
                <p>Best regards,<br>GrantThrive Platform</p>
                '''
            }
        }
        
        template = email_templates.get(event_type, {
            'subject': f'Grant Update - {grant_title}',
            'body': f'<p>You have a new update regarding your grant application {grant_id}.</p>'
        })
        
        return template['subject'], template['body']
    
    def _generate_custom_email(self, event_type, grant_data, custom_message):
        """
        Generate custom email content
        
        Args:
            event_type (NotificationEvent): Type of notification
            grant_data (dict): Grant information
            custom_message (str): Custom message content
            
        Returns:
            tuple: (subject: str, body: str)
        """
        grant_title = grant_data.get('grant_title', 'Grant Application')
        
        subject = f'Grant Update - {grant_title}'
        body = f'''
        <h2>Grant Program Update</h2>
        <div style="background-color: #f8f9fa; padding: 15px; border-left: 4px solid #007bff; margin: 20px 0;">
            {custom_message}
        </div>
        <p>Best regards,<br>GrantThrive Platform</p>
        '''
        
        return subject, body
    
    def _generate_standard_sms(self, event_type, grant_data):
        """
        Generate standard SMS content for event type
        (This uses the existing SMS templates from the SMS connector)
        
        Args:
            event_type (NotificationEvent): Type of notification
            grant_data (dict): Grant information
            
        Returns:
            str: SMS message content
        """
        # This will use the existing SMS templates from SMSConnector._generate_grant_message
        # We return None here to indicate that the SMS service should use its built-in templates
        return None
    
    def send_bulk_notification(self, bulk_notification_data):
        """
        Send notifications to multiple recipients
        
        Args:
            bulk_notification_data (dict): Bulk notification information
            
        Returns:
            tuple: (success: bool, results_summary: dict or error_message: str)
        """
        try:
            recipients = bulk_notification_data.get('recipients', [])
            base_notification = bulk_notification_data.get('notification_template', {})
            
            if not recipients:
                return False, "No recipients provided"
            
            results_summary = {
                'total_recipients': len(recipients),
                'successful_deliveries': 0,
                'failed_deliveries': 0,
                'email_sent': 0,
                'sms_sent': 0,
                'results': []
            }
            
            for recipient in recipients:
                # Merge recipient data with base notification
                notification_data = {**base_notification, **recipient}
                
                success, delivery_result = self.send_notification(notification_data)
                
                if success:
                    results_summary['successful_deliveries'] += 1
                    if delivery_result.get('email_sent'):
                        results_summary['email_sent'] += 1
                    if delivery_result.get('sms_sent'):
                        results_summary['sms_sent'] += 1
                else:
                    results_summary['failed_deliveries'] += 1
                
                results_summary['results'].append({
                    'recipient': recipient.get('applicant_id', 'unknown'),
                    'success': success,
                    'delivery_result': delivery_result
                })
            
            overall_success = results_summary['successful_deliveries'] > 0
            return overall_success, results_summary
            
        except Exception as e:
            return False, f"Bulk notification error: {str(e)}"
    
    def get_notification_history(self, council_id, limit=100):
        """
        Get notification history for a council
        
        Args:
            council_id (str): Council identifier
            limit (int): Maximum number of records to return
            
        Returns:
            list: Notification history
        """
        council_notifications = [
            log for log in self.notification_log 
            if log.get('council_id') == council_id
        ]
        
        # Sort by timestamp (most recent first)
        council_notifications.sort(
            key=lambda x: x.get('timestamp', ''), 
            reverse=True
        )
        
        return council_notifications[:limit]
    
    def get_notification_statistics(self, council_id, start_date=None, end_date=None):
        """
        Get notification statistics for a council
        
        Args:
            council_id (str): Council identifier
            start_date (str): Start date filter (optional)
            end_date (str): End date filter (optional)
            
        Returns:
            dict: Notification statistics
        """
        notifications = self.get_notification_history(council_id, limit=None)
        
        # Filter by date range if provided
        if start_date or end_date:
            filtered_notifications = []
            for notif in notifications:
                notif_date = notif.get('timestamp', '')
                if start_date and notif_date < start_date:
                    continue
                if end_date and notif_date > end_date:
                    continue
                filtered_notifications.append(notif)
            notifications = filtered_notifications
        
        stats = {
            'total_notifications': len(notifications),
            'emails_sent': sum(1 for n in notifications if n.get('email_sent')),
            'sms_sent': sum(1 for n in notifications if n.get('sms_sent')),
            'successful_deliveries': sum(1 for n in notifications if n.get('email_sent') or n.get('sms_sent')),
            'failed_deliveries': sum(1 for n in notifications if not n.get('email_sent') and not n.get('sms_sent')),
            'by_event_type': {},
            'by_preference': {}
        }
        
        # Count by event type and preference
        for notif in notifications:
            event_type = notif.get('event_type', 'unknown')
            preference = notif.get('effective_preference', 'unknown')
            
            stats['by_event_type'][event_type] = stats['by_event_type'].get(event_type, 0) + 1
            stats['by_preference'][preference] = stats['by_preference'].get(preference, 0) + 1
        
        return stats

