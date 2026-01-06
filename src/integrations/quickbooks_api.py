"""
QuickBooks API Integration for GrantThrive Platform
Handles financial data synchronization with QuickBooks accounting system
"""

import os
import requests
from datetime import datetime
from .base_connector import BaseConnector

class QuickBooksConnector(BaseConnector):
    """
    QuickBooks API connector for syncing grant financial data
    with QuickBooks accounting system for budget tracking and reporting.
    """
    
    def __init__(self):
        super().__init__('QUICKBOOKS')
        self.company_id = self._get_credential('COMPANY_ID')
        self.access_token = None
        self.refresh_token = self._get_credential('REFRESH_TOKEN')
        
    def authenticate(self):
        """
        Authenticate with QuickBooks using OAuth 2.0
        Returns access token for API calls
        """
        if self.refresh_token:
            return self._refresh_access_token()
        else:
            return False, "No refresh token available. Please re-authorize the application."
    
    def _refresh_access_token(self):
        """
        Refresh the access token using the refresh token
        """
        auth_url = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
        
        auth_data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token
        }
        
        headers = {
            'Authorization': f'Basic {self.api_key}',  # Base64 encoded client_id:client_secret
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            response = requests.post(auth_url, data=auth_data, headers=headers)
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result.get('access_token')
                return True, "Successfully authenticated with QuickBooks"
            else:
                return False, f"Authentication failed: {response.text}"
        except Exception as e:
            return False, f"Authentication error: {str(e)}"
    
    def create_customer(self, organization_data):
        """
        Create a customer record in QuickBooks for grant recipient organization
        
        Args:
            organization_data (dict): Organization information
            
        Returns:
            tuple: (success: bool, customer_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare QuickBooks customer data
        customer_data = {
            "Name": organization_data.get('organization_name', ''),
            "CompanyName": organization_data.get('organization_name', ''),
            "BillAddr": {
                "Line1": organization_data.get('address_line1', ''),
                "Line2": organization_data.get('address_line2', ''),
                "City": organization_data.get('city', ''),
                "CountrySubDivisionCode": organization_data.get('state', ''),
                "PostalCode": organization_data.get('postal_code', ''),
                "Country": organization_data.get('country', 'Australia')
            },
            "PrimaryEmailAddr": {
                "Address": organization_data.get('email', '')
            },
            "PrimaryPhone": {
                "FreeFormNumber": organization_data.get('phone', '')
            },
            "Notes": f"Grant recipient organization - Created via GrantThrive on {datetime.now().strftime('%Y-%m-%d')}"
        }
        
        try:
            print(f"Creating QuickBooks customer: {customer_data}")
            
            # Simulated customer creation
            customer_id = f"cust_{organization_data.get('organization_name', 'unknown').replace(' ', '_').lower()}"
            
            return True, customer_id
            
        except Exception as e:
            return False, f"QuickBooks customer creation error: {str(e)}"
    
    def create_invoice(self, grant_data):
        """
        Create an invoice in QuickBooks for grant funding
        
        Args:
            grant_data (dict): Grant and recipient information
            
        Returns:
            tuple: (success: bool, invoice_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # First ensure customer exists
        customer_success, customer_id = self.create_customer(grant_data.get('organization', {}))
        if not customer_success:
            return False, f"Failed to create customer: {customer_id}"
        
        # Prepare QuickBooks invoice data
        invoice_data = {
            "Line": [{
                "Amount": grant_data.get('funding_amount', 0),
                "DetailType": "SalesItemLineDetail",
                "SalesItemLineDetail": {
                    "ItemRef": {
                        "value": "1",  # Default service item
                        "name": "Grant Funding"
                    },
                    "Qty": 1,
                    "UnitPrice": grant_data.get('funding_amount', 0)
                }
            }],
            "CustomerRef": {
                "value": customer_id
            },
            "TxnDate": datetime.now().strftime('%Y-%m-%d'),
            "DueDate": grant_data.get('payment_due_date', datetime.now().strftime('%Y-%m-%d')),
            "PrivateNote": f"Grant funding for: {grant_data.get('grant_title', 'Grant Application')}",
            "CustomerMemo": {
                "value": f"Grant Reference: {grant_data.get('grant_id', 'N/A')}"
            }
        }
        
        try:
            print(f"Creating QuickBooks invoice: {invoice_data}")
            
            # Simulated invoice creation
            invoice_id = f"inv_{grant_data.get('grant_id', 'unknown')}"
            
            return True, invoice_id
            
        except Exception as e:
            return False, f"QuickBooks invoice creation error: {str(e)}"
    
    def create_expense(self, expense_data):
        """
        Create an expense record in QuickBooks for grant-related costs
        
        Args:
            expense_data (dict): Expense information
            
        Returns:
            tuple: (success: bool, expense_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare QuickBooks expense data
        expense_record = {
            "AccountRef": {
                "value": "1",  # Default expense account
                "name": "Grant Administration Expenses"
            },
            "PaymentType": "Cash",
            "TotalAmt": expense_data.get('amount', 0),
            "TxnDate": expense_data.get('date', datetime.now().strftime('%Y-%m-%d')),
            "PrivateNote": expense_data.get('description', 'Grant-related expense'),
            "Line": [{
                "Amount": expense_data.get('amount', 0),
                "DetailType": "AccountBasedExpenseLineDetail",
                "AccountBasedExpenseLineDetail": {
                    "AccountRef": {
                        "value": "1",
                        "name": "Grant Administration"
                    }
                }
            }]
        }
        
        try:
            print(f"Creating QuickBooks expense: {expense_record}")
            
            # Simulated expense creation
            expense_id = f"exp_{expense_data.get('reference', 'unknown')}"
            
            return True, expense_id
            
        except Exception as e:
            return False, f"QuickBooks expense creation error: {str(e)}"
    
    def get_financial_report(self, start_date, end_date):
        """
        Generate financial report for grant activities
        
        Args:
            start_date (str): Start date in YYYY-MM-DD format
            end_date (str): End date in YYYY-MM-DD format
            
        Returns:
            tuple: (success: bool, report_data: dict or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        try:
            # Simulated financial report
            report_data = {
                "period": f"{start_date} to {end_date}",
                "total_grants_issued": 125000.00,
                "total_expenses": 8500.00,
                "net_grant_activity": 116500.00,
                "outstanding_invoices": 25000.00,
                "grant_categories": {
                    "Community Development": 45000.00,
                    "Youth Programs": 35000.00,
                    "Environmental": 25000.00,
                    "Arts & Culture": 20000.00
                }
            }
            
            return True, report_data
            
        except Exception as e:
            return False, f"Error generating financial report: {str(e)}"
    
    def sync_grant_budget(self, grant_data):
        """
        Sync grant budget information to QuickBooks for tracking
        
        Args:
            grant_data (dict): Grant budget information
            
        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Create customer if needed
            customer_success, customer_id = self.create_customer(grant_data.get('organization', {}))
            
            # Create invoice for funding
            invoice_success, invoice_id = self.create_invoice(grant_data)
            
            if customer_success and invoice_success:
                return True, f"Grant budget synced to QuickBooks - Customer: {customer_id}, Invoice: {invoice_id}"
            else:
                return False, "Failed to sync complete grant budget to QuickBooks"
                
        except Exception as e:
            return False, f"Grant budget sync error: {str(e)}"

