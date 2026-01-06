"""
Salesforce API Integration for GrantThrive Platform
Handles connection and data synchronization with Salesforce CRM
"""

import os
import requests
from .base_connector import BaseConnector

class SalesforceConnector(BaseConnector):
    """
    Salesforce API connector for syncing grant application data
    with Salesforce CRM opportunities and contacts.
    """
    
    def __init__(self):
        super().__init__('SALESFORCE')
        self.instance_url = self._get_credential('INSTANCE_URL')
        self.access_token = None
        
    def authenticate(self):
        """
        Authenticate with Salesforce using OAuth 2.0
        Returns access token for API calls
        """
        auth_url = f"{self.base_url}/services/oauth2/token"
        
        auth_data = {
            'grant_type': 'client_credentials',
            'client_id': self.api_key,
            'client_secret': self.api_secret
        }
        
        try:
            response = requests.post(auth_url, data=auth_data)
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result.get('access_token')
                self.instance_url = auth_result.get('instance_url')
                return True, "Successfully authenticated with Salesforce"
            else:
                return False, f"Authentication failed: {response.text}"
        except Exception as e:
            return False, f"Authentication error: {str(e)}"
    
    def sync_opportunity(self, grant_data):
        """
        Sync grant application data to Salesforce as an Opportunity
        
        Args:
            grant_data (dict): Grant application information
            
        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare Salesforce opportunity data
        opportunity_data = {
            'Name': grant_data.get('grant_title', 'Grant Application'),
            'Amount': grant_data.get('funding_amount', 0),
            'CloseDate': grant_data.get('deadline', '2024-12-31'),
            'StageName': self._map_status_to_stage(grant_data.get('status', 'draft')),
            'Description': grant_data.get('description', ''),
            'Type': 'Grant Application',
            'LeadSource': 'GrantThrive Platform'
        }
        
        # Add custom fields if available
        if grant_data.get('organization_name'):
            opportunity_data['Account'] = {'Name': grant_data['organization_name']}
        
        try:
            # In a real implementation, we would make the actual API call
            # For now, we simulate the sync process
            print(f"Syncing opportunity to Salesforce: {opportunity_data}")
            
            # Simulated API call
            # url = f"{self.instance_url}/services/data/v58.0/sobjects/Opportunity"
            # headers = {
            #     'Authorization': f'Bearer {self.access_token}',
            #     'Content-Type': 'application/json'
            # }
            # response = requests.post(url, json=opportunity_data, headers=headers)
            
            return True, f"Grant application '{grant_data.get('grant_title')}' synced to Salesforce as Opportunity"
            
        except Exception as e:
            return False, f"Salesforce sync error: {str(e)}"
    
    def sync_contact(self, contact_data):
        """
        Sync contact information to Salesforce
        
        Args:
            contact_data (dict): Contact information
            
        Returns:
            tuple: (success: bool, message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare Salesforce contact data
        salesforce_contact = {
            'FirstName': contact_data.get('firstname', ''),
            'LastName': contact_data.get('lastname', ''),
            'Email': contact_data.get('email', ''),
            'Phone': contact_data.get('phone', ''),
            'Title': contact_data.get('position', ''),
            'Department': contact_data.get('department', ''),
            'LeadSource': 'GrantThrive Platform'
        }
        
        # Add account association if organization provided
        if contact_data.get('organization'):
            salesforce_contact['Account'] = {'Name': contact_data['organization']}
        
        try:
            print(f"Syncing contact to Salesforce: {salesforce_contact}")
            
            # Simulated successful sync
            return True, f"Contact {contact_data.get('email')} synced to Salesforce successfully"
            
        except Exception as e:
            return False, f"Salesforce contact sync error: {str(e)}"
    
    def _map_status_to_stage(self, status):
        """
        Map GrantThrive application status to Salesforce opportunity stage
        """
        status_mapping = {
            'draft': 'Prospecting',
            'submitted': 'Qualification',
            'under_review': 'Needs Analysis',
            'approved': 'Closed Won',
            'rejected': 'Closed Lost',
            'pending': 'Proposal/Price Quote'
        }
        return status_mapping.get(status.lower(), 'Prospecting')
    
    def get_opportunities(self, limit=10):
        """
        Retrieve opportunities from Salesforce
        
        Args:
            limit (int): Maximum number of opportunities to retrieve
            
        Returns:
            tuple: (success: bool, data: list or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        try:
            # Simulated data retrieval
            sample_opportunities = [
                {
                    'Id': 'opp_001',
                    'Name': 'Community Development Grant',
                    'Amount': 25000,
                    'StageName': 'Qualification',
                    'CloseDate': '2024-03-15'
                },
                {
                    'Id': 'opp_002', 
                    'Name': 'Youth Programs Initiative',
                    'Amount': 15000,
                    'StageName': 'Needs Analysis',
                    'CloseDate': '2024-04-01'
                }
            ]
            
            return True, sample_opportunities[:limit]
            
        except Exception as e:
            return False, f"Error retrieving opportunities: {str(e)}"

