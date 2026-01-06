"""
MYOB API Integration for GrantThrive Platform
Handles financial data synchronization with MYOB accounting system
Popular in Australia and New Zealand for council financial management
"""

import os
import requests
from datetime import datetime
from .base_connector import BaseConnector

class MYOBConnector(BaseConnector):
    """
    MYOB API connector for syncing grant financial data
    with MYOB AccountRight or MYOB Essentials for Australian councils.
    """
    
    def __init__(self):
        super().__init__('MYOB')
        self.company_file_id = self._get_credential('COMPANY_FILE_ID')
        self.access_token = None
        self.refresh_token = self._get_credential('REFRESH_TOKEN')
        
    def authenticate(self):
        """
        Authenticate with MYOB using OAuth 2.0
        Returns access token for API calls
        """
        auth_url = "https://secure.myob.com/oauth2/v1/authorize"
        
        auth_data = {
            'client_id': self.api_key,
            'client_secret': self.api_secret,
            'grant_type': 'client_credentials',
            'scope': 'CompanyFile'
        }
        
        try:
            response = requests.post(auth_url, data=auth_data)
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result.get('access_token')
                return True, "Successfully authenticated with MYOB"
            else:
                return False, f"MYOB authentication failed: {response.text}"
        except Exception as e:
            return False, f"MYOB authentication error: {str(e)}"
    
    def create_customer_card(self, organization_data):
        """
        Create a customer card in MYOB for grant recipient organization
        
        Args:
            organization_data (dict): Organization information
            
        Returns:
            tuple: (success: bool, customer_uid: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare MYOB customer card data
        customer_card = {
            "CompanyName": organization_data.get('organization_name', ''),
            "LastName": organization_data.get('contact_lastname', ''),
            "FirstName": organization_data.get('contact_firstname', ''),
            "IsIndividual": False,
            "DisplayID": organization_data.get('abn', '').replace(' ', '') or f"GRANT{datetime.now().strftime('%Y%m%d')}",
            "Addresses": [{
                "Location": 1,  # Primary address
                "Street": organization_data.get('address_line1', ''),
                "City": organization_data.get('city', ''),
                "State": organization_data.get('state', ''),
                "PostCode": organization_data.get('postal_code', ''),
                "Country": organization_data.get('country', 'Australia'),
                "Phone1": organization_data.get('phone', ''),
                "Email": organization_data.get('email', '')
            }],
            "Notes": f"Grant recipient - Created via GrantThrive on {datetime.now().strftime('%d/%m/%Y')}",
            "CustomField1": {
                "Label": "Grant Program",
                "Value": organization_data.get('grant_program', '')
            },
            "CustomField2": {
                "Label": "ABN",
                "Value": organization_data.get('abn', '')
            }
        }
        
        try:
            print(f"Creating MYOB customer card: {customer_card}")
            
            # Simulated customer card creation
            customer_uid = f"myob_cust_{organization_data.get('organization_name', 'unknown').replace(' ', '_').lower()}"
            
            return True, customer_uid
            
        except Exception as e:
            return False, f"MYOB customer card creation error: {str(e)}"
    
    def create_sale_invoice(self, grant_data):
        """
        Create a sale invoice in MYOB for grant funding disbursement
        
        Args:
            grant_data (dict): Grant and recipient information
            
        Returns:
            tuple: (success: bool, invoice_number: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Ensure customer exists
        customer_success, customer_uid = self.create_customer_card(grant_data.get('organization', {}))
        if not customer_success:
            return False, f"Failed to create customer: {customer_uid}"
        
        # Prepare MYOB sale invoice data
        invoice_data = {
            "Number": f"GRANT-{grant_data.get('grant_id', datetime.now().strftime('%Y%m%d'))}",
            "Date": datetime.now().strftime('%Y-%m-%d'),
            "Customer": {
                "UID": customer_uid
            },
            "Lines": [{
                "Type": "Transaction",
                "Description": f"Grant Funding: {grant_data.get('grant_title', 'Grant Application')}",
                "Account": {
                    "DisplayID": "4-1000",  # Grant Income account
                    "Name": "Grant Income"
                },
                "Total": grant_data.get('funding_amount', 0),
                "TaxCode": {
                    "Code": "FRE"  # GST Free for grants
                }
            }],
            "Terms": {
                "PaymentIsDue": "OnADate",
                "DueDate": grant_data.get('payment_due_date', datetime.now().strftime('%Y-%m-%d'))
            },
            "Comment": f"Grant Reference: {grant_data.get('grant_id', 'N/A')}\nProgram: {grant_data.get('grant_program', 'N/A')}"
        }
        
        try:
            print(f"Creating MYOB sale invoice: {invoice_data}")
            
            # Simulated invoice creation
            invoice_number = invoice_data["Number"]
            
            return True, invoice_number
            
        except Exception as e:
            return False, f"MYOB sale invoice creation error: {str(e)}"
    
    def create_spend_money_transaction(self, expense_data):
        """
        Create a spend money transaction in MYOB for grant administration costs
        
        Args:
            expense_data (dict): Expense information
            
        Returns:
            tuple: (success: bool, transaction_number: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare MYOB spend money transaction
        transaction_data = {
            "Date": expense_data.get('date', datetime.now().strftime('%Y-%m-%d')),
            "Memo": expense_data.get('description', 'Grant administration expense'),
            "Account": {
                "DisplayID": "1-1100",  # Bank account
                "Name": "Operating Account"
            },
            "Lines": [{
                "Type": "Transaction",
                "Description": expense_data.get('description', 'Grant administration'),
                "Account": {
                    "DisplayID": "6-1200",  # Administration expenses
                    "Name": "Grant Administration Expenses"
                },
                "Total": expense_data.get('amount', 0),
                "TaxCode": {
                    "Code": "GST"  # GST applicable for expenses
                }
            }],
            "PaymentMethod": expense_data.get('payment_method', 'Electronic')
        }
        
        try:
            print(f"Creating MYOB spend money transaction: {transaction_data}")
            
            # Simulated transaction creation
            transaction_number = f"SM{datetime.now().strftime('%Y%m%d')}-{expense_data.get('reference', '001')}"
            
            return True, transaction_number
            
        except Exception as e:
            return False, f"MYOB spend money transaction error: {str(e)}"
    
    def generate_grant_report(self, start_date, end_date):
        """
        Generate grant activity report from MYOB data
        
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
            # Simulated MYOB grant report
            report_data = {
                "report_period": f"{start_date} to {end_date}",
                "total_grants_disbursed": 185000.00,
                "total_administration_costs": 12500.00,
                "net_grant_expenditure": 197500.00,
                "gst_collected": 1250.00,
                "outstanding_payments": 35000.00,
                "grant_programs": {
                    "Community Infrastructure": 75000.00,
                    "Youth Development": 45000.00,
                    "Environmental Sustainability": 35000.00,
                    "Arts & Cultural": 30000.00
                },
                "monthly_breakdown": [
                    {"month": "January", "disbursed": 45000.00, "admin_costs": 3200.00},
                    {"month": "February", "disbursed": 52000.00, "admin_costs": 3800.00},
                    {"month": "March", "disbursed": 88000.00, "admin_costs": 5500.00}
                ]
            }
            
            return True, report_data
            
        except Exception as e:
            return False, f"Error generating MYOB grant report: {str(e)}"
    
    def sync_grant_financials(self, grant_data):
        """
        Complete financial sync for a grant to MYOB
        
        Args:
            grant_data (dict): Complete grant information
            
        Returns:
            tuple: (success: bool, sync_summary: dict or error_message: str)
        """
        try:
            sync_results = {}
            
            # Create customer card
            customer_success, customer_uid = self.create_customer_card(grant_data.get('organization', {}))
            sync_results['customer'] = {'success': customer_success, 'uid': customer_uid}
            
            # Create sale invoice for grant funding
            invoice_success, invoice_number = self.create_sale_invoice(grant_data)
            sync_results['invoice'] = {'success': invoice_success, 'number': invoice_number}
            
            # Create administration expense if provided
            if grant_data.get('admin_fee'):
                admin_expense = {
                    'amount': grant_data['admin_fee'],
                    'description': f"Administration fee for grant {grant_data.get('grant_id')}",
                    'reference': grant_data.get('grant_id')
                }
                expense_success, transaction_number = self.create_spend_money_transaction(admin_expense)
                sync_results['admin_expense'] = {'success': expense_success, 'number': transaction_number}
            
            # Determine overall success
            overall_success = customer_success and invoice_success
            
            if overall_success:
                return True, sync_results
            else:
                return False, f"Partial sync failure: {sync_results}"
                
        except Exception as e:
            return False, f"MYOB grant financial sync error: {str(e)}"
    
    def get_company_file_info(self):
        """
        Get information about the connected MYOB company file
        
        Returns:
            tuple: (success: bool, company_info: dict or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        try:
            # Simulated company file information
            company_info = {
                "CompanyName": "Mount Isa City Council",
                "ABN": "12 345 678 901",
                "CurrentFinancialYear": "2024",
                "LastModified": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "CompanyFileId": self.company_file_id,
                "ProductVersion": "2024.1",
                "ProductLevel": "AccountRight Plus"
            }
            
            return True, company_info
            
        except Exception as e:
            return False, f"Error retrieving company file info: {str(e)}"

