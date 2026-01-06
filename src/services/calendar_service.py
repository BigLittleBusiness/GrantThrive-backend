"""
Smart Calendar Integration Service for GrantThrive Platform
Enables one-click calendar integration for deadlines, meetings, and milestones
"""

import os
from datetime import datetime, timedelta
from urllib.parse import quote
import json

class CalendarService:
    """
    Service for generating calendar integration links and managing calendar events
    """
    
    def __init__(self):
        self.timezone = "Australia/Sydney"  # Default timezone
        
    def generate_google_calendar_link(self, event_data):
        """
        Generate Google Calendar add event link
        
        Args:
            event_data (dict): Event information
            
        Returns:
            tuple: (success: bool, calendar_url: str or error_message: str)
        """
        try:
            title = event_data.get('title', 'Grant Event')
            start_date = event_data.get('start_date')
            end_date = event_data.get('end_date')
            description = event_data.get('description', '')
            location = event_data.get('location', '')
            
            if not start_date:
                return False, "Start date is required"
            
            # Parse dates
            if isinstance(start_date, str):
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            else:
                start_dt = start_date
                
            if end_date:
                if isinstance(end_date, str):
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                else:
                    end_dt = end_date
            else:
                # Default to 1 hour duration
                end_dt = start_dt + timedelta(hours=1)
            
            # Format dates for Google Calendar (UTC format)
            start_formatted = start_dt.strftime('%Y%m%dT%H%M%SZ')
            end_formatted = end_dt.strftime('%Y%m%dT%H%M%SZ')
            
            # Build Google Calendar URL
            base_url = "https://calendar.google.com/calendar/render"
            params = {
                'action': 'TEMPLATE',
                'text': title,
                'dates': f"{start_formatted}/{end_formatted}",
                'details': description,
                'location': location,
                'sf': 'true',
                'output': 'xml'
            }
            
            # Construct URL
            param_string = '&'.join([f"{key}={quote(str(value))}" for key, value in params.items() if value])
            calendar_url = f"{base_url}?{param_string}"
            
            return True, calendar_url
            
        except Exception as e:
            return False, f"Error generating Google Calendar link: {str(e)}"
    
    def generate_outlook_calendar_link(self, event_data):
        """
        Generate Outlook Calendar add event link
        
        Args:
            event_data (dict): Event information
            
        Returns:
            tuple: (success: bool, calendar_url: str or error_message: str)
        """
        try:
            title = event_data.get('title', 'Grant Event')
            start_date = event_data.get('start_date')
            end_date = event_data.get('end_date')
            description = event_data.get('description', '')
            location = event_data.get('location', '')
            
            if not start_date:
                return False, "Start date is required"
            
            # Parse dates
            if isinstance(start_date, str):
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            else:
                start_dt = start_date
                
            if end_date:
                if isinstance(end_date, str):
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                else:
                    end_dt = end_date
            else:
                end_dt = start_dt + timedelta(hours=1)
            
            # Format dates for Outlook (ISO format)
            start_formatted = start_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            end_formatted = end_dt.strftime('%Y-%m-%dT%H:%M:%S.000Z')
            
            # Build Outlook Calendar URL
            base_url = "https://outlook.live.com/calendar/0/deeplink/compose"
            params = {
                'subject': title,
                'startdt': start_formatted,
                'enddt': end_formatted,
                'body': description,
                'location': location,
                'path': '/calendar/action/compose',
                'rru': 'addevent'
            }
            
            # Construct URL
            param_string = '&'.join([f"{key}={quote(str(value))}" for key, value in params.items() if value])
            calendar_url = f"{base_url}?{param_string}"
            
            return True, calendar_url
            
        except Exception as e:
            return False, f"Error generating Outlook Calendar link: {str(e)}"
    
    def generate_apple_calendar_link(self, event_data):
        """
        Generate Apple Calendar (.ics) file content
        
        Args:
            event_data (dict): Event information
            
        Returns:
            tuple: (success: bool, ics_content: str or error_message: str)
        """
        try:
            title = event_data.get('title', 'Grant Event')
            start_date = event_data.get('start_date')
            end_date = event_data.get('end_date')
            description = event_data.get('description', '')
            location = event_data.get('location', '')
            
            if not start_date:
                return False, "Start date is required"
            
            # Parse dates
            if isinstance(start_date, str):
                start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            else:
                start_dt = start_date
                
            if end_date:
                if isinstance(end_date, str):
                    end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                else:
                    end_dt = end_date
            else:
                end_dt = start_dt + timedelta(hours=1)
            
            # Format dates for ICS (UTC format)
            start_formatted = start_dt.strftime('%Y%m%dT%H%M%SZ')
            end_formatted = end_dt.strftime('%Y%m%dT%H%M%SZ')
            created_formatted = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            
            # Generate unique UID
            uid = f"grantthrive-{start_formatted}-{hash(title)}"
            
            # Create ICS content
            ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//GrantThrive//Grant Management//EN
CALSCALE:GREGORIAN
METHOD:PUBLISH
BEGIN:VEVENT
UID:{uid}
DTSTART:{start_formatted}
DTEND:{end_formatted}
DTSTAMP:{created_formatted}
CREATED:{created_formatted}
SUMMARY:{title}
DESCRIPTION:{description}
LOCATION:{location}
STATUS:CONFIRMED
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR"""
            
            return True, ics_content
            
        except Exception as e:
            return False, f"Error generating Apple Calendar file: {str(e)}"
    
    def generate_all_calendar_links(self, event_data):
        """
        Generate calendar links for all major calendar providers
        
        Args:
            event_data (dict): Event information
            
        Returns:
            tuple: (success: bool, calendar_links: dict or error_message: str)
        """
        try:
            calendar_links = {}
            
            # Google Calendar
            success, google_link = self.generate_google_calendar_link(event_data)
            if success:
                calendar_links['google'] = google_link
            
            # Outlook Calendar
            success, outlook_link = self.generate_outlook_calendar_link(event_data)
            if success:
                calendar_links['outlook'] = outlook_link
            
            # Apple Calendar
            success, ics_content = self.generate_apple_calendar_link(event_data)
            if success:
                calendar_links['apple_ics'] = ics_content
            
            if not calendar_links:
                return False, "Failed to generate any calendar links"
            
            return True, calendar_links
            
        except Exception as e:
            return False, f"Error generating calendar links: {str(e)}"
    
    def create_grant_deadline_event(self, grant_data):
        """
        Create calendar event data for grant deadline
        
        Args:
            grant_data (dict): Grant information
            
        Returns:
            dict: Calendar event data
        """
        grant_title = grant_data.get('title', 'Grant Application')
        deadline = grant_data.get('deadline')
        council_name = grant_data.get('council_name', 'Council')
        funding_amount = grant_data.get('funding_amount', 0)
        grant_url = grant_data.get('grant_url', '')
        
        # Set deadline as all-day event
        if isinstance(deadline, str):
            deadline_dt = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
        else:
            deadline_dt = deadline
        
        # Set to end of day for deadline
        deadline_dt = deadline_dt.replace(hour=23, minute=59, second=59)
        
        event_data = {
            'title': f"📅 Grant Deadline: {grant_title}",
            'start_date': deadline_dt - timedelta(hours=1),  # 1 hour before deadline
            'end_date': deadline_dt,
            'description': f"""Grant Application Deadline
            
Grant: {grant_title}
Council: {council_name}
Funding: ${funding_amount:,.0f}

⚠️ Application must be submitted before this deadline.

Apply now: {grant_url}

Generated by GrantThrive Platform""",
            'location': f"{council_name} (Online Application)"
        }
        
        return event_data
    
    def create_grant_meeting_event(self, meeting_data):
        """
        Create calendar event data for grant-related meeting
        
        Args:
            meeting_data (dict): Meeting information
            
        Returns:
            dict: Calendar event data
        """
        meeting_title = meeting_data.get('title', 'Grant Meeting')
        start_time = meeting_data.get('start_time')
        end_time = meeting_data.get('end_time')
        location = meeting_data.get('location', '')
        description = meeting_data.get('description', '')
        attendees = meeting_data.get('attendees', [])
        
        event_data = {
            'title': f"🤝 {meeting_title}",
            'start_date': start_time,
            'end_date': end_time,
            'description': f"""{description}

Attendees: {', '.join(attendees) if attendees else 'TBD'}

Generated by GrantThrive Platform""",
            'location': location
        }
        
        return event_data
    
    def create_grant_milestone_event(self, milestone_data):
        """
        Create calendar event data for grant milestone
        
        Args:
            milestone_data (dict): Milestone information
            
        Returns:
            dict: Calendar event data
        """
        milestone_title = milestone_data.get('title', 'Grant Milestone')
        due_date = milestone_data.get('due_date')
        grant_title = milestone_data.get('grant_title', 'Grant')
        description = milestone_data.get('description', '')
        
        event_data = {
            'title': f"🎯 {milestone_title} - {grant_title}",
            'start_date': due_date,
            'end_date': due_date,
            'description': f"""Grant Milestone Due

Milestone: {milestone_title}
Grant: {grant_title}

{description}

Generated by GrantThrive Platform""",
            'location': 'Grant Management'
        }
        
        return event_data
    
    def get_calendar_integration_options(self):
        """
        Get available calendar integration options
        
        Returns:
            dict: Calendar integration options
        """
        return {
            'google': {
                'name': 'Google Calendar',
                'icon': '📅',
                'description': 'Add to Google Calendar',
                'color': '#4285f4',
                'supported_features': ['events', 'reminders', 'sharing']
            },
            'outlook': {
                'name': 'Outlook Calendar',
                'icon': '📆',
                'description': 'Add to Outlook Calendar',
                'color': '#0078d4',
                'supported_features': ['events', 'reminders', 'teams_integration']
            },
            'apple': {
                'name': 'Apple Calendar',
                'icon': '🍎',
                'description': 'Download .ics file for Apple Calendar',
                'color': '#007aff',
                'supported_features': ['events', 'reminders', 'siri_integration']
            },
            'generic': {
                'name': 'Other Calendar Apps',
                'icon': '📋',
                'description': 'Download .ics file for any calendar app',
                'color': '#6b7280',
                'supported_features': ['events', 'basic_reminders']
            }
        }
    
    def create_reminder_schedule(self, event_date, reminder_preferences=None):
        """
        Create reminder schedule for calendar events
        
        Args:
            event_date (datetime): Event date
            reminder_preferences (dict): User reminder preferences
            
        Returns:
            list: Reminder schedule
        """
        if not reminder_preferences:
            reminder_preferences = {
                'one_week_before': True,
                'three_days_before': True,
                'one_day_before': True,
                'two_hours_before': True
            }
        
        reminders = []
        
        if reminder_preferences.get('one_week_before'):
            reminders.append({
                'time': event_date - timedelta(weeks=1),
                'type': 'email',
                'message': 'Grant deadline in 1 week'
            })
        
        if reminder_preferences.get('three_days_before'):
            reminders.append({
                'time': event_date - timedelta(days=3),
                'type': 'notification',
                'message': 'Grant deadline in 3 days'
            })
        
        if reminder_preferences.get('one_day_before'):
            reminders.append({
                'time': event_date - timedelta(days=1),
                'type': 'notification',
                'message': 'Grant deadline tomorrow'
            })
        
        if reminder_preferences.get('two_hours_before'):
            reminders.append({
                'time': event_date - timedelta(hours=2),
                'type': 'notification',
                'message': 'Grant deadline in 2 hours'
            })
        
        return reminders

