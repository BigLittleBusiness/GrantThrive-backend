"""
SMS API Integration for GrantThrive Platform
Handles SMS notifications for grant applications and status updates
Multi-provider SMS gateway integration for reliable message delivery
"""

import os
import requests
from datetime import datetime
from .base_connector import BaseConnector

class SMSConnector(BaseConnector):
    """
    SMS API connector supporting multiple providers for reliable
    SMS notifications and reminders for grant applications.
    """
    
    def __init__(self, provider='twilio'):
        super().__init__('SMS')
        self.provider = provider.lower()
        self.setup_provider()
        
    def setup_provider(self):
        """
        Setup SMS provider configuration
        """
        if self.provider == 'twilio':
            self.base_url = "https://api.twilio.com/2010-04-01"
            self.account_sid = self._get_credential('TWILIO_ACCOUNT_SID')
            self.auth_token = self._get_credential('TWILIO_AUTH_TOKEN')
            self.from_number = self._get_credential('TWILIO_FROM_NUMBER')
            
        elif self.provider == 'messagemedia':
            self.base_url = "https://api.messagemedia.com/v1"
            self.api_key = self._get_credential('MESSAGEMEDIA_API_KEY')
            self.api_secret = self._get_credential('MESSAGEMEDIA_API_SECRET')
            
        elif self.provider == 'clicksend':
            self.base_url = "https://rest.clicksend.com/v3"
            self.username = self._get_credential('CLICKSEND_USERNAME')
            self.api_key = self._get_credential('CLICKSEND_API_KEY')
            
        else:
            raise ValueError(f"Unsupported SMS provider: {self.provider}")
    
    def authenticate(self):
        """
        Authenticate with SMS provider
        Returns authentication status
        """
        try:
            if self.provider == 'twilio':
                if self.account_sid and self.auth_token:
                    return True, f"Twilio credentials configured (SID: {self.account_sid[:8]}...)"
                else:
                    return False, "Twilio credentials not configured"
                    
            elif self.provider == 'messagemedia':
                if self.api_key and self.api_secret:
                    return True, "MessageMedia credentials configured"
                else:
                    return False, "MessageMedia credentials not configured"
                    
            elif self.provider == 'clicksend':
                if self.username and self.api_key:
                    return True, "ClickSend credentials configured"
                else:
                    return False, "ClickSend credentials not configured"
                    
        except Exception as e:
            return False, f"SMS authentication error: {str(e)}"
    
    def send_sms(self, to_number, message, message_type='notification'):
        """
        Send SMS message
        
        Args:
            to_number (str): Recipient phone number (international format)
            message (str): SMS message content
            message_type (str): Type of message for tracking
            
        Returns:
            tuple: (success: bool, message_id: str or error_message: str)
        """
        auth_success, auth_message = self.authenticate()
        if not auth_success:
            return False, auth_message
        
        try:
            # Validate phone number format
            clean_number = self._clean_phone_number(to_number)
            if not clean_number:
                return False, "Invalid phone number format"
            
            # Validate message length
            if len(message) > 1600:  # SMS limit
                return False, "Message too long (max 1600 characters)"
            
            if self.provider == 'twilio':
                return self._send_twilio_sms(clean_number, message, message_type)
            elif self.provider == 'messagemedia':
                return self._send_messagemedia_sms(clean_number, message, message_type)
            elif self.provider == 'clicksend':
                return self._send_clicksend_sms(clean_number, message, message_type)
                
        except Exception as e:
            return False, f"SMS sending error: {str(e)}"
    
    def _send_twilio_sms(self, to_number, message, message_type):
        """
        Send SMS via Twilio
        """
        try:
            url = f"{self.base_url}/Accounts/{self.account_sid}/Messages.json"
            
            data = {
                'From': self.from_number,
                'To': to_number,
                'Body': message
            }
            
            # Simulated Twilio SMS sending
            message_id = f"twilio_msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            print(f"Sending Twilio SMS to {to_number}: {message[:50]}...")
            
            return True, message_id
            
        except Exception as e:
            return False, f"Twilio SMS error: {str(e)}"
    
    def _send_messagemedia_sms(self, to_number, message, message_type):
        """
        Send SMS via MessageMedia (Australian provider)
        """
        try:
            url = f"{self.base_url}/messages"
            
            headers = {
                'Authorization': f'Basic {self.api_key}:{self.api_secret}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'messages': [{
                    'content': message,
                    'destination_number': to_number,
                    'format': 'SMS',
                    'message_expiry_timestamp': (datetime.now().timestamp() + 3600) * 1000  # 1 hour expiry
                }]
            }
            
            # Simulated MessageMedia SMS sending
            message_id = f"mm_msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            print(f"Sending MessageMedia SMS to {to_number}: {message[:50]}...")
            
            return True, message_id
            
        except Exception as e:
            return False, f"MessageMedia SMS error: {str(e)}"
    
    def _send_clicksend_sms(self, to_number, message, message_type):
        """
        Send SMS via ClickSend
        """
        try:
            url = f"{self.base_url}/sms/send"
            
            headers = {
                'Authorization': f'Basic {self.username}:{self.api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'messages': [{
                    'body': message,
                    'to': to_number,
                    'source': 'GrantThrive'
                }]
            }
            
            # Simulated ClickSend SMS sending
            message_id = f"cs_msg_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            print(f"Sending ClickSend SMS to {to_number}: {message[:50]}...")
            
            return True, message_id
            
        except Exception as e:
            return False, f"ClickSend SMS error: {str(e)}"
    
    def send_grant_notification(self, to_number, grant_data, notification_type):
        """
        Send grant-specific SMS notification
        
        Args:
            to_number (str): Recipient phone number
            grant_data (dict): Grant information
            notification_type (str): Type of notification
            
        Returns:
            tuple: (success: bool, message_id: str or error_message: str)
        """
        try:
            message = self._generate_grant_message(grant_data, notification_type)
            if not message:
                return False, f"Unknown notification type: {notification_type}"
            
            return self.send_sms(to_number, message, notification_type)
            
        except Exception as e:
            return False, f"Grant notification error: {str(e)}"
    
    def _generate_grant_message(self, grant_data, notification_type):
        """
        Generate SMS message based on notification type
        """
        grant_title = grant_data.get('grant_title', 'Grant Application')
        grant_id = grant_data.get('grant_id', 'N/A')
        organization = grant_data.get('organization_name', '')
        amount = grant_data.get('funding_amount', 0)
        
        messages = {
            'application_received': f"""
GrantThrive: Your application for "{grant_title}" (ID: {grant_id}) has been received. We'll review it and notify you of the outcome. Thank you for applying!
            """.strip(),
            
            'application_approved': f"""
🎉 GREAT NEWS! Your grant application "{grant_title}" (ID: {grant_id}) has been APPROVED for ${amount:,.2f}. Check your email for next steps. Congratulations!
            """.strip(),
            
            'application_rejected': f"""
GrantThrive: Unfortunately, your application for "{grant_title}" (ID: {grant_id}) was not successful this time. Check your email for feedback and future opportunities.
            """.strip(),
            
            'deadline_reminder': f"""
⏰ REMINDER: Your grant application "{grant_title}" (ID: {grant_id}) deadline is approaching. Please submit all required documents soon. Don't miss out!
            """.strip(),
            
            'document_required': f"""
📄 ACTION REQUIRED: Additional documents needed for your grant application "{grant_title}" (ID: {grant_id}). Please check your GrantThrive account and upload the required files.
            """.strip(),
            
            'payment_processed': f"""
💰 PAYMENT PROCESSED: Grant funding of ${amount:,.2f} for "{grant_title}" (ID: {grant_id}) has been transferred to your account. Thank you for your community work!
            """.strip(),
            
            'report_due': f"""
📊 REPORT DUE: Your progress report for grant "{grant_title}" (ID: {grant_id}) is due soon. Please submit via your GrantThrive account to maintain compliance.
            """.strip(),
            
            'meeting_reminder': f"""
📅 MEETING REMINDER: You have a grant review meeting scheduled for "{grant_title}" (ID: {grant_id}). Check your email for meeting details and agenda.
            """.strip()
        }
        
        return messages.get(notification_type)
    
    def send_bulk_sms(self, recipients, message, message_type='bulk'):
        """
        Send SMS to multiple recipients
        
        Args:
            recipients (list): List of phone numbers
            message (str): SMS message content
            message_type (str): Type of message
            
        Returns:
            tuple: (success: bool, results: list or error_message: str)
        """
        if len(recipients) > 1000:
            return False, "Maximum 1000 recipients per bulk SMS"
        
        results = []
        successful = 0
        failed = 0
        
        for recipient in recipients:
            try:
                success, message_id = self.send_sms(recipient, message, message_type)
                
                result = {
                    'recipient': recipient,
                    'success': success,
                    'message_id': message_id if success else None,
                    'error': None if success else message_id
                }
                
                results.append(result)
                
                if success:
                    successful += 1
                else:
                    failed += 1
                    
            except Exception as e:
                results.append({
                    'recipient': recipient,
                    'success': False,
                    'message_id': None,
                    'error': str(e)
                })
                failed += 1
        
        summary = {
            'total_sent': len(recipients),
            'successful': successful,
            'failed': failed,
            'results': results
        }
        
        return True, summary
    
    def get_message_status(self, message_id):
        """
        Get SMS delivery status
        
        Args:
            message_id (str): SMS message ID
            
        Returns:
            tuple: (success: bool, status_data: dict or error_message: str)
        """
        try:
            # Simulated message status
            status_data = {
                'message_id': message_id,
                'status': 'delivered',  # sent, delivered, failed, unknown
                'sent_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'delivered_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'provider': self.provider,
                'cost': 0.05  # Cost in AUD
            }
            
            return True, status_data
            
        except Exception as e:
            return False, f"SMS status check error: {str(e)}"
    
    def _clean_phone_number(self, phone_number):
        """
        Clean and validate phone number format
        
        Args:
            phone_number (str): Phone number to clean
            
        Returns:
            str: Cleaned phone number in international format or None if invalid
        """
        try:
            # Remove all non-digit characters
            clean = ''.join(filter(str.isdigit, phone_number))
            
            # Handle Australian numbers
            if clean.startswith('04') and len(clean) == 10:
                return f"+61{clean[1:]}"  # Convert to international format
            elif clean.startswith('614') and len(clean) == 11:
                return f"+{clean}"
            elif clean.startswith('61') and len(clean) == 11:
                return f"+{clean}"
            
            # Handle New Zealand numbers
            elif clean.startswith('02') and len(clean) == 10:
                return f"+64{clean[1:]}"  # Convert to international format
            elif clean.startswith('642') and len(clean) == 11:
                return f"+{clean}"
            elif clean.startswith('64') and len(clean) == 10:
                return f"+{clean}"
            
            # Handle international format
            elif clean.startswith('1') and len(clean) == 11:  # US/Canada
                return f"+{clean}"
            elif clean.startswith('44') and len(clean) >= 10:  # UK
                return f"+{clean}"
            
            # If already in international format with +
            elif phone_number.startswith('+') and len(clean) >= 10:
                return phone_number
            
            return None
            
        except Exception:
            return None
    
    def get_sms_status(self):
        """
        Check SMS service status
        
        Returns:
            tuple: (success: bool, status_info: dict or error_message: str)
        """
        try:
            auth_success, auth_message = self.authenticate()
            
            status_info = {
                'service_name': f'SMS Service ({self.provider.title()})',
                'provider': self.provider,
                'api_status': 'operational' if auth_success else 'authentication_failed',
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'credentials_configured': auth_success,
                'supported_countries': ['Australia', 'New Zealand', 'International'],
                'features': ['Single SMS', 'Bulk SMS', 'Delivery Status', 'Grant Notifications']
            }
            
            if not auth_success:
                status_info['error_details'] = auth_message
            
            return True, status_info
            
        except Exception as e:
            return False, f"SMS status check error: {str(e)}"

