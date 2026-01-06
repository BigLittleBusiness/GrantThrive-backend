"""
HubSpot API Integration for GrantThrive Platform
Handles CRM synchronization and contact management
"""

import os
import requests
from datetime import datetime
from typing import Dict, List, Optional

class HubSpotConnector:
    """
    Connector for HubSpot CRM integration
    """
    
    def __init__(self):
        self.api_key = os.getenv('HUBSPOT_API_KEY', 'demo-hubspot-key')
        self.base_url = 'https://api.hubapi.com'
        self.headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
    
    def test_connection(self) -> Dict:
        """
        Test HubSpot API connection
        
        Returns:
            dict: Connection test result
        """
        try:
            # Test with account info endpoint
            response = requests.get(
                f'{self.base_url}/account-info/v3/details',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                account_info = response.json()
                return {
                    'success': True,
                    'message': 'HubSpot connection successful',
                    'account_name': account_info.get('companyName', 'Unknown'),
                    'portal_id': account_info.get('portalId', 'Unknown')
                }
            else:
                return {
                    'success': False,
                    'error': f'HubSpot API error: {response.status_code}',
                    'message': response.text
                }
                
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': 'Connection failed',
                'message': str(e)
            }
    
    def sync_contact(self, contact_data: Dict) -> Dict:
        """
        Sync contact to HubSpot
        
        Args:
            contact_data (dict): Contact information
            
        Returns:
            dict: Sync result
        """
        try:
            # Prepare HubSpot contact properties
            properties = {
                'email': contact_data.get('email'),
                'firstname': contact_data.get('first_name'),
                'lastname': contact_data.get('last_name'),
                'company': contact_data.get('organization'),
                'phone': contact_data.get('phone'),
                'website': contact_data.get('website'),
                'city': contact_data.get('city'),
                'state': contact_data.get('state'),
                'country': contact_data.get('country', 'Australia'),
                'lifecyclestage': 'lead',
                'lead_source': 'GrantThrive Platform'
            }
            
            # Remove None values
            properties = {k: v for k, v in properties.items() if v is not None}
            
            # Create or update contact
            payload = {'properties': properties}
            
            response = requests.post(
                f'{self.base_url}/crm/v3/objects/contacts',
                headers=self.headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                contact = response.json()
                return {
                    'success': True,
                    'hubspot_contact_id': contact['id'],
                    'message': 'Contact synced successfully'
                }
            elif response.status_code == 409:
                # Contact exists, try to update
                return self._update_existing_contact(contact_data)
            else:
                return {
                    'success': False,
                    'error': f'HubSpot API error: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': 'Contact sync failed',
                'message': str(e)
            }
    
    def _update_existing_contact(self, contact_data: Dict) -> Dict:
        """
        Update existing contact in HubSpot
        """
        try:
            email = contact_data.get('email')
            if not email:
                return {
                    'success': False,
                    'error': 'Email required for contact update'
                }
            
            # Find contact by email
            search_response = requests.post(
                f'{self.base_url}/crm/v3/objects/contacts/search',
                headers=self.headers,
                json={
                    'filterGroups': [{
                        'filters': [{
                            'propertyName': 'email',
                            'operator': 'EQ',
                            'value': email
                        }]
                    }]
                },
                timeout=10
            )
            
            if search_response.status_code == 200:
                search_results = search_response.json()
                if search_results['total'] > 0:
                    contact_id = search_results['results'][0]['id']
                    
                    # Update contact
                    properties = {
                        'firstname': contact_data.get('first_name'),
                        'lastname': contact_data.get('last_name'),
                        'company': contact_data.get('organization'),
                        'phone': contact_data.get('phone'),
                        'website': contact_data.get('website'),
                        'city': contact_data.get('city'),
                        'state': contact_data.get('state')
                    }
                    
                    # Remove None values
                    properties = {k: v for k, v in properties.items() if v is not None}
                    
                    update_response = requests.patch(
                        f'{self.base_url}/crm/v3/objects/contacts/{contact_id}',
                        headers=self.headers,
                        json={'properties': properties},
                        timeout=10
                    )
                    
                    if update_response.status_code == 200:
                        return {
                            'success': True,
                            'hubspot_contact_id': contact_id,
                            'message': 'Contact updated successfully'
                        }
            
            return {
                'success': False,
                'error': 'Failed to update existing contact'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': 'Contact update failed',
                'message': str(e)
            }
    
    def create_deal(self, deal_data: Dict) -> Dict:
        """
        Create deal in HubSpot
        
        Args:
            deal_data (dict): Deal information
            
        Returns:
            dict: Deal creation result
        """
        try:
            properties = {
                'dealname': deal_data.get('grant_title'),
                'amount': deal_data.get('funding_amount'),
                'dealstage': 'appointmentscheduled',
                'pipeline': 'default',
                'closedate': deal_data.get('deadline'),
                'deal_source': 'GrantThrive Platform',
                'description': deal_data.get('description', '')
            }
            
            # Remove None values
            properties = {k: v for k, v in properties.items() if v is not None}
            
            payload = {'properties': properties}
            
            response = requests.post(
                f'{self.base_url}/crm/v3/objects/deals',
                headers=self.headers,
                json=payload,
                timeout=10
            )
            
            if response.status_code in [200, 201]:
                deal = response.json()
                return {
                    'success': True,
                    'hubspot_deal_id': deal['id'],
                    'message': 'Deal created successfully'
                }
            else:
                return {
                    'success': False,
                    'error': f'HubSpot API error: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': 'Deal creation failed',
                'message': str(e)
            }
    
    def get_contact_by_email(self, email: str) -> Dict:
        """
        Get contact from HubSpot by email
        
        Args:
            email (str): Contact email
            
        Returns:
            dict: Contact information
        """
        try:
            response = requests.get(
                f'{self.base_url}/crm/v3/objects/contacts/{email}',
                headers=self.headers,
                params={'idProperty': 'email'},
                timeout=10
            )
            
            if response.status_code == 200:
                contact = response.json()
                return {
                    'success': True,
                    'contact': contact
                }
            elif response.status_code == 404:
                return {
                    'success': False,
                    'error': 'Contact not found'
                }
            else:
                return {
                    'success': False,
                    'error': f'HubSpot API error: {response.status_code}',
                    'message': response.text
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': 'Contact retrieval failed',
                'message': str(e)
            }
    
    def get_integration_status(self) -> Dict:
        """
        Get HubSpot integration status
        
        Returns:
            dict: Integration status
        """
        connection_test = self.test_connection()
        
        return {
            'service': 'HubSpot',
            'status': 'connected' if connection_test['success'] else 'disconnected',
            'last_sync': datetime.now().isoformat(),
            'account_info': connection_test.get('account_name', 'Unknown') if connection_test['success'] else None,
            'error': connection_test.get('error') if not connection_test['success'] else None
        }

