"""
Communication Preferences Model for GrantThrive Platform
Allows council admins to configure SMS vs Email communication preferences
"""

from datetime import datetime
from enum import Enum

class CommunicationType(Enum):
    EMAIL = "email"
    SMS = "sms"
    BOTH = "both"
    NONE = "none"

class NotificationEvent(Enum):
    APPLICATION_RECEIVED = "application_received"
    APPLICATION_APPROVED = "application_approved"
    APPLICATION_REJECTED = "application_rejected"
    DEADLINE_REMINDER = "deadline_reminder"
    DOCUMENT_REQUIRED = "document_required"
    PAYMENT_PROCESSED = "payment_processed"
    REPORT_DUE = "report_due"
    MEETING_REMINDER = "meeting_reminder"
    GENERAL_UPDATE = "general_update"

class CommunicationPreferences:
    """
    Model for storing council communication preferences
    """
    
    def __init__(self, council_id):
        self.council_id = council_id
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        
        # Default communication preferences - can be overridden by admin
        self.default_preferences = {
            NotificationEvent.APPLICATION_RECEIVED: CommunicationType.EMAIL,
            NotificationEvent.APPLICATION_APPROVED: CommunicationType.BOTH,  # Important news via both
            NotificationEvent.APPLICATION_REJECTED: CommunicationType.EMAIL,
            NotificationEvent.DEADLINE_REMINDER: CommunicationType.SMS,     # Urgent reminders via SMS
            NotificationEvent.DOCUMENT_REQUIRED: CommunicationType.EMAIL,
            NotificationEvent.PAYMENT_PROCESSED: CommunicationType.BOTH,    # Important news via both
            NotificationEvent.REPORT_DUE: CommunicationType.EMAIL,
            NotificationEvent.MEETING_REMINDER: CommunicationType.SMS,      # Urgent reminders via SMS
            NotificationEvent.GENERAL_UPDATE: CommunicationType.EMAIL
        }
        
        # Admin-configured preferences (overrides defaults)
        self.custom_preferences = {}
        
        # Global settings
        self.email_enabled = True
        self.sms_enabled = True
        self.sms_provider = "twilio"  # Default SMS provider
        
        # Applicant preference override settings
        self.allow_applicant_preference_override = True
        self.require_phone_number_for_sms = True
        
        # Business hours and timing settings
        self.business_hours_only_sms = True
        self.business_start_hour = 8   # 8 AM
        self.business_end_hour = 18    # 6 PM
        self.timezone = "Australia/Sydney"
        
        # Cost management
        self.sms_daily_limit = 1000
        self.sms_monthly_budget = 500.00  # AUD
        
    def get_communication_preference(self, event_type):
        """
        Get communication preference for a specific event type
        
        Args:
            event_type (NotificationEvent): Type of notification event
            
        Returns:
            CommunicationType: Preferred communication method
        """
        # Check if admin has set a custom preference
        if event_type in self.custom_preferences:
            return self.custom_preferences[event_type]
        
        # Fall back to default preference
        return self.default_preferences.get(event_type, CommunicationType.EMAIL)
    
    def set_communication_preference(self, event_type, communication_type):
        """
        Set communication preference for a specific event type
        
        Args:
            event_type (NotificationEvent): Type of notification event
            communication_type (CommunicationType): Preferred communication method
        """
        self.custom_preferences[event_type] = communication_type
        self.updated_at = datetime.now()
    
    def should_send_email(self, event_type):
        """
        Check if email should be sent for this event type
        
        Args:
            event_type (NotificationEvent): Type of notification event
            
        Returns:
            bool: True if email should be sent
        """
        if not self.email_enabled:
            return False
            
        preference = self.get_communication_preference(event_type)
        return preference in [CommunicationType.EMAIL, CommunicationType.BOTH]
    
    def should_send_sms(self, event_type):
        """
        Check if SMS should be sent for this event type
        
        Args:
            event_type (NotificationEvent): Type of notification event
            
        Returns:
            bool: True if SMS should be sent
        """
        if not self.sms_enabled:
            return False
            
        preference = self.get_communication_preference(event_type)
        return preference in [CommunicationType.SMS, CommunicationType.BOTH]
    
    def is_within_business_hours(self):
        """
        Check if current time is within business hours for SMS
        
        Returns:
            bool: True if within business hours
        """
        if not self.business_hours_only_sms:
            return True
            
        from datetime import datetime
        import pytz
        
        try:
            tz = pytz.timezone(self.timezone)
            current_time = datetime.now(tz)
            current_hour = current_time.hour
            
            return self.business_start_hour <= current_hour < self.business_end_hour
        except:
            # If timezone handling fails, default to allowing SMS
            return True
    
    def get_preferences_summary(self):
        """
        Get a summary of all communication preferences
        
        Returns:
            dict: Summary of preferences
        """
        summary = {
            'council_id': self.council_id,
            'email_enabled': self.email_enabled,
            'sms_enabled': self.sms_enabled,
            'sms_provider': self.sms_provider,
            'allow_applicant_override': self.allow_applicant_preference_override,
            'business_hours_only_sms': self.business_hours_only_sms,
            'business_hours': f"{self.business_start_hour}:00 - {self.business_end_hour}:00",
            'timezone': self.timezone,
            'sms_daily_limit': self.sms_daily_limit,
            'sms_monthly_budget': self.sms_monthly_budget,
            'preferences': {}
        }
        
        # Add all event preferences
        for event in NotificationEvent:
            preference = self.get_communication_preference(event)
            summary['preferences'][event.value] = {
                'communication_type': preference.value,
                'will_send_email': self.should_send_email(event),
                'will_send_sms': self.should_send_sms(event)
            }
        
        return summary
    
    def update_global_settings(self, settings):
        """
        Update global communication settings
        
        Args:
            settings (dict): Settings to update
        """
        if 'email_enabled' in settings:
            self.email_enabled = settings['email_enabled']
        
        if 'sms_enabled' in settings:
            self.sms_enabled = settings['sms_enabled']
            
        if 'sms_provider' in settings:
            self.sms_provider = settings['sms_provider']
            
        if 'allow_applicant_preference_override' in settings:
            self.allow_applicant_preference_override = settings['allow_applicant_preference_override']
            
        if 'business_hours_only_sms' in settings:
            self.business_hours_only_sms = settings['business_hours_only_sms']
            
        if 'business_start_hour' in settings:
            self.business_start_hour = settings['business_start_hour']
            
        if 'business_end_hour' in settings:
            self.business_end_hour = settings['business_end_hour']
            
        if 'timezone' in settings:
            self.timezone = settings['timezone']
            
        if 'sms_daily_limit' in settings:
            self.sms_daily_limit = settings['sms_daily_limit']
            
        if 'sms_monthly_budget' in settings:
            self.sms_monthly_budget = settings['sms_monthly_budget']
        
        self.updated_at = datetime.now()
    
    def reset_to_defaults(self):
        """
        Reset all preferences to default values
        """
        self.custom_preferences = {}
        self.email_enabled = True
        self.sms_enabled = True
        self.sms_provider = "twilio"
        self.allow_applicant_preference_override = True
        self.business_hours_only_sms = True
        self.business_start_hour = 8
        self.business_end_hour = 18
        self.timezone = "Australia/Sydney"
        self.sms_daily_limit = 1000
        self.sms_monthly_budget = 500.00
        self.updated_at = datetime.now()
    
    def to_dict(self):
        """
        Convert preferences to dictionary for storage/API
        
        Returns:
            dict: Preferences as dictionary
        """
        return {
            'council_id': self.council_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'email_enabled': self.email_enabled,
            'sms_enabled': self.sms_enabled,
            'sms_provider': self.sms_provider,
            'allow_applicant_preference_override': self.allow_applicant_preference_override,
            'business_hours_only_sms': self.business_hours_only_sms,
            'business_start_hour': self.business_start_hour,
            'business_end_hour': self.business_end_hour,
            'timezone': self.timezone,
            'sms_daily_limit': self.sms_daily_limit,
            'sms_monthly_budget': self.sms_monthly_budget,
            'custom_preferences': {
                event.value: comm_type.value 
                for event, comm_type in self.custom_preferences.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Create preferences from dictionary
        
        Args:
            data (dict): Preferences data
            
        Returns:
            CommunicationPreferences: Preferences object
        """
        prefs = cls(data['council_id'])
        
        prefs.created_at = datetime.fromisoformat(data.get('created_at', datetime.now().isoformat()))
        prefs.updated_at = datetime.fromisoformat(data.get('updated_at', datetime.now().isoformat()))
        prefs.email_enabled = data.get('email_enabled', True)
        prefs.sms_enabled = data.get('sms_enabled', True)
        prefs.sms_provider = data.get('sms_provider', 'twilio')
        prefs.allow_applicant_preference_override = data.get('allow_applicant_preference_override', True)
        prefs.business_hours_only_sms = data.get('business_hours_only_sms', True)
        prefs.business_start_hour = data.get('business_start_hour', 8)
        prefs.business_end_hour = data.get('business_end_hour', 18)
        prefs.timezone = data.get('timezone', 'Australia/Sydney')
        prefs.sms_daily_limit = data.get('sms_daily_limit', 1000)
        prefs.sms_monthly_budget = data.get('sms_monthly_budget', 500.00)
        
        # Convert custom preferences back to enums
        custom_prefs = data.get('custom_preferences', {})
        for event_str, comm_type_str in custom_prefs.items():
            try:
                event = NotificationEvent(event_str)
                comm_type = CommunicationType(comm_type_str)
                prefs.custom_preferences[event] = comm_type
            except ValueError:
                # Skip invalid enum values
                continue
        
        return prefs


class ApplicantCommunicationPreferences:
    """
    Model for storing individual applicant communication preferences
    (if council allows applicant preference override)
    """
    
    def __init__(self, applicant_id, council_id):
        self.applicant_id = applicant_id
        self.council_id = council_id
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
        
        # Applicant preferences (only used if council allows override)
        self.preferred_communication = CommunicationType.EMAIL  # Default to email
        self.phone_number = None
        self.phone_verified = False
        self.email_verified = True  # Assume email is verified during registration
        
        # Opt-out settings
        self.opted_out_sms = False
        self.opted_out_email = False
        self.opted_out_all = False
    
    def can_receive_sms(self):
        """
        Check if applicant can receive SMS
        
        Returns:
            bool: True if SMS can be sent
        """
        return (
            not self.opted_out_sms and 
            not self.opted_out_all and
            self.phone_number and 
            self.phone_verified
        )
    
    def can_receive_email(self):
        """
        Check if applicant can receive email
        
        Returns:
            bool: True if email can be sent
        """
        return (
            not self.opted_out_email and 
            not self.opted_out_all and
            self.email_verified
        )
    
    def get_effective_preference(self, council_preferences, event_type):
        """
        Get effective communication preference considering both council and applicant settings
        
        Args:
            council_preferences (CommunicationPreferences): Council preferences
            event_type (NotificationEvent): Type of notification
            
        Returns:
            CommunicationType: Effective communication preference
        """
        # If council doesn't allow override, use council preference
        if not council_preferences.allow_applicant_preference_override:
            return council_preferences.get_communication_preference(event_type)
        
        # If applicant has opted out of everything, return NONE
        if self.opted_out_all:
            return CommunicationType.NONE
        
        # Get council preference as baseline
        council_pref = council_preferences.get_communication_preference(event_type)
        
        # Apply applicant preferences
        if self.preferred_communication == CommunicationType.EMAIL:
            if council_pref == CommunicationType.BOTH:
                return CommunicationType.EMAIL if self.can_receive_email() else CommunicationType.NONE
            elif council_pref == CommunicationType.SMS:
                return CommunicationType.EMAIL if self.can_receive_email() else CommunicationType.NONE
            else:
                return council_pref if self.can_receive_email() else CommunicationType.NONE
        
        elif self.preferred_communication == CommunicationType.SMS:
            if council_pref == CommunicationType.BOTH:
                return CommunicationType.SMS if self.can_receive_sms() else CommunicationType.EMAIL
            elif council_pref == CommunicationType.EMAIL:
                return CommunicationType.SMS if self.can_receive_sms() else CommunicationType.EMAIL
            else:
                return council_pref if self.can_receive_sms() else CommunicationType.NONE
        
        elif self.preferred_communication == CommunicationType.BOTH:
            return council_pref  # Use council preference
        
        else:  # NONE
            return CommunicationType.NONE
    
    def to_dict(self):
        """
        Convert applicant preferences to dictionary
        
        Returns:
            dict: Preferences as dictionary
        """
        return {
            'applicant_id': self.applicant_id,
            'council_id': self.council_id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'preferred_communication': self.preferred_communication.value,
            'phone_number': self.phone_number,
            'phone_verified': self.phone_verified,
            'email_verified': self.email_verified,
            'opted_out_sms': self.opted_out_sms,
            'opted_out_email': self.opted_out_email,
            'opted_out_all': self.opted_out_all
        }

