"""
Xero API Integration for GrantThrive Platform
Handles financial data synchronization with Xero accounting system
Popular cloud-based accounting solution for Australian councils
"""

import os
import requests
from datetime import datetime, timedelta
from .base_connector import BaseConnector

class XeroConnector(BaseConnector):
    """
    Xero API connector for syncing grant financial data
    with Xero accounting system for modern cloud-based financial management.
    """
    
    def __init__(self):
        super().__init__('XERO')
        self.tenant_id = self._get_credential('TENANT_ID')
        self.access_token = None
        self.refresh_token = self._get_credential('REFRESH_TOKEN')
        self.base_url = "https://api.xero.com/api.xro/2.0"
        
    def authenticate(self):
        """
        Authenticate with Xero using OAuth 2.0
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
        auth_url = "https://identity.xero.com/connect/token"
        
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
                return True, "Successfully authenticated with Xero"
            else:
                return False, f"Xero authentication failed: {response.text}"
        except Exception as e:
            return False, f"Xero authentication error: {str(e)}"
    
    def create_contact(self, organization_data):
        """
        Create a contact in Xero for grant recipient organization
        
        Args:
            organization_data (dict): Organization information
            
        Returns:
            tuple: (success: bool, contact_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare Xero contact data
        contact_data = {
            "Name": organization_data.get('organization_name', ''),
            "ContactNumber": organization_data.get('abn', '').replace(' ', '') or f"GRANT{datetime.now().strftime('%Y%m%d')}",
            "AccountNumber": f"GRANT-{organization_data.get('organization_name', 'ORG').replace(' ', '').upper()[:10]}",
            "ContactStatus": "ACTIVE",
            "Addresses": [{
                "AddressType": "STREET",
                "AddressLine1": organization_data.get('address_line1', ''),
                "AddressLine2": organization_data.get('address_line2', ''),
                "City": organization_data.get('city', ''),
                "Region": organization_data.get('state', ''),
                "PostalCode": organization_data.get('postal_code', ''),
                "Country": organization_data.get('country', 'Australia')
            }],
            "Phones": [{
                "PhoneType": "DEFAULT",
                "PhoneNumber": organization_data.get('phone', '')
            }],
            "EmailAddress": organization_data.get('email', ''),
            "TaxNumber": organization_data.get('abn', ''),
            "DefaultCurrency": "AUD",
            "IsSupplier": False,
            "IsCustomer": True
        }
        
        try:
            print(f"Creating Xero contact: {contact_data}")
            
            # Simulated contact creation
            contact_id = f"xero_contact_{organization_data.get('organization_name', 'unknown').replace(' ', '_').lower()}"
            
            return True, contact_id
            
        except Exception as e:
            return False, f"Xero contact creation error: {str(e)}"
    
    def create_invoice(self, grant_data):
        """
        Create an invoice in Xero for grant funding
        
        Args:
            grant_data (dict): Grant and recipient information
            
        Returns:
            tuple: (success: bool, invoice_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Ensure contact exists
        contact_success, contact_id = self.create_contact(grant_data.get('organization', {}))
        if not contact_success:
            return False, f"Failed to create contact: {contact_id}"
        
        # Prepare Xero invoice data
        invoice_data = {
            "Type": "ACCREC",  # Accounts Receivable (Sales Invoice)
            "Contact": {
                "ContactID": contact_id
            },
            "Date": datetime.now().strftime('%Y-%m-%d'),
            "DueDate": grant_data.get('payment_due_date', (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')),
            "InvoiceNumber": f"GRANT-{grant_data.get('grant_id', datetime.now().strftime('%Y%m%d'))}",
            "Reference": f"Grant Program: {grant_data.get('grant_program', 'N/A')}",
            "BrandingThemeID": None,  # Use default branding
            "CurrencyCode": "AUD",
            "Status": "AUTHORISED",
            "LineAmountTypes": "Exclusive",
            "LineItems": [{
                "Description": f"Grant Funding: {grant_data.get('grant_title', 'Grant Application')}",
                "Quantity": 1,
                "UnitAmount": grant_data.get('funding_amount', 0),
                "AccountCode": "200",  # Grant Income account
                "TaxType": "NONE",  # Grants are typically GST-free
                "LineAmount": grant_data.get('funding_amount', 0)
            }]
        }
        
        try:
            print(f"Creating Xero invoice: {invoice_data}")
            
            # Simulated invoice creation
            invoice_id = f"xero_inv_{grant_data.get('grant_id', 'unknown')}"
            
            return True, invoice_id
            
        except Exception as e:
            return False, f"Xero invoice creation error: {str(e)}"
    
    def create_bank_transaction(self, expense_data):
        """
        Create a bank transaction in Xero for grant-related expenses
        
        Args:
            expense_data (dict): Expense information
            
        Returns:
            tuple: (success: bool, transaction_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare Xero bank transaction data
        transaction_data = {
            "Type": "SPEND",
            "Contact": {
                "Name": expense_data.get('payee', 'Grant Administration')
            },
            "Date": expense_data.get('date', datetime.now().strftime('%Y-%m-%d')),
            "Reference": expense_data.get('reference', f"Grant Admin - {datetime.now().strftime('%Y%m%d')}"),
            "IsReconciled": False,
            "BankAccount": {
                "Code": "090",  # Operating bank account
                "Name": "Council Operating Account"
            },
            "LineItems": [{
                "Description": expense_data.get('description', 'Grant administration expense'),
                "UnitAmount": expense_data.get('amount', 0),
                "AccountCode": "400",  # Administration expenses
                "TaxType": "INPUT",  # GST on expenses
                "LineAmount": expense_data.get('amount', 0)
            }]
        }
        
        try:
            print(f"Creating Xero bank transaction: {transaction_data}")
            
            # Simulated transaction creation
            transaction_id = f"xero_txn_{expense_data.get('reference', 'unknown')}"
            
            return True, transaction_id
            
        except Exception as e:
            return False, f"Xero bank transaction creation error: {str(e)}"
    
    def create_budget(self, budget_data):
        """
        Create or update budget in Xero for grant programs
        
        Args:
            budget_data (dict): Budget information
            
        Returns:
            tuple: (success: bool, budget_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare Xero budget data
        budget_info = {
            "BudgetID": f"GRANT-BUDGET-{budget_data.get('financial_year', datetime.now().year)}",
            "Type": "OVERALL",
            "Description": f"Grant Program Budget - {budget_data.get('program_name', 'All Programs')}",
            "BudgetLines": []
        }
        
        # Add budget lines for different grant categories
        for category, amount in budget_data.get('categories', {}).items():
            budget_info["BudgetLines"].append({
                "AccountID": "200",  # Grant Income account
                "AccountCode": "200",
                "Amount": amount,
                "Description": f"Budget allocation for {category}"
            })
        
        try:
            print(f"Creating Xero budget: {budget_info}")
            
            # Simulated budget creation
            budget_id = budget_info["BudgetID"]
            
            return True, budget_id
            
        except Exception as e:
            return False, f"Xero budget creation error: {str(e)}"
    
    def generate_financial_report(self, start_date, end_date):
        """
        Generate comprehensive financial report for grant activities
        
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
            # Simulated comprehensive Xero financial report
            report_data = {
                "report_period": f"{start_date} to {end_date}",
                "currency": "AUD",
                "total_grant_income": 245000.00,
                "total_grant_expenses": 18500.00,
                "net_grant_position": 226500.00,
                "gst_liability": 1850.00,
                "outstanding_receivables": 45000.00,
                "cash_position": 180500.00,
                "grant_categories": {
                    "Community Development": {
                        "budgeted": 80000.00,
                        "actual": 75000.00,
                        "variance": 5000.00,
                        "variance_percent": 6.25
                    },
                    "Youth Programs": {
                        "budgeted": 60000.00,
                        "actual": 65000.00,
                        "variance": -5000.00,
                        "variance_percent": -8.33
                    },
                    "Environmental": {
                        "budgeted": 50000.00,
                        "actual": 45000.00,
                        "variance": 5000.00,
                        "variance_percent": 10.0
                    },
                    "Arts & Culture": {
                        "budgeted": 40000.00,
                        "actual": 42000.00,
                        "variance": -2000.00,
                        "variance_percent": -5.0
                    }
                },
                "monthly_trends": [
                    {"month": "Jan", "income": 65000.00, "expenses": 4200.00, "net": 60800.00},
                    {"month": "Feb", "income": 78000.00, "expenses": 5800.00, "net": 72200.00},
                    {"month": "Mar", "income": 102000.00, "expenses": 8500.00, "net": 93500.00}
                ],
                "key_metrics": {
                    "average_grant_size": 12250.00,
                    "grants_processed": 20,
                    "processing_cost_per_grant": 925.00,
                    "efficiency_ratio": 92.45
                }
            }
            
            return True, report_data
            
        except Exception as e:
            return False, f"Error generating Xero financial report: {str(e)}"
    
    def sync_complete_grant(self, grant_data):
        """
        Complete synchronization of grant data to Xero
        
        Args:
            grant_data (dict): Complete grant information
            
        Returns:
            tuple: (success: bool, sync_summary: dict or error_message: str)
        """
        try:
            sync_results = {}
            
            # Create contact for organization
            contact_success, contact_id = self.create_contact(grant_data.get('organization', {}))
            sync_results['contact'] = {'success': contact_success, 'id': contact_id}
            
            # Create invoice for grant funding
            invoice_success, invoice_id = self.create_invoice(grant_data)
            sync_results['invoice'] = {'success': invoice_success, 'id': invoice_id}
            
            # Create bank transaction for administration fee if applicable
            if grant_data.get('admin_fee'):
                admin_expense = {
                    'amount': grant_data['admin_fee'],
                    'description': f"Administration fee for grant {grant_data.get('grant_id')}",
                    'reference': f"ADMIN-{grant_data.get('grant_id')}",
                    'payee': 'Grant Administration'
                }
                expense_success, transaction_id = self.create_bank_transaction(admin_expense)
                sync_results['admin_expense'] = {'success': expense_success, 'id': transaction_id}
            
            # Update budget if budget data provided
            if grant_data.get('budget_impact'):
                budget_success, budget_id = self.create_budget(grant_data['budget_impact'])
                sync_results['budget'] = {'success': budget_success, 'id': budget_id}
            
            # Determine overall success
            overall_success = contact_success and invoice_success
            
            if overall_success:
                sync_summary = {
                    "status": "success",
                    "grant_id": grant_data.get('grant_id'),
                    "organization": grant_data.get('organization', {}).get('organization_name'),
                    "amount": grant_data.get('funding_amount'),
                    "xero_records": sync_results,
                    "sync_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                return True, sync_summary
            else:
                return False, f"Partial sync failure: {sync_results}"
                
        except Exception as e:
            return False, f"Xero complete grant sync error: {str(e)}"
    
    def get_organization_info(self):
        """
        Get information about the connected Xero organization
        
        Returns:
            tuple: (success: bool, org_info: dict or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        try:
            # Simulated organization information
            org_info = {
                "Name": "Mount Isa City Council",
                "LegalName": "Mount Isa City Council",
                "PaysTax": True,
                "Version": "AU",
                "OrganisationType": "COMPANY",
                "BaseCurrency": "AUD",
                "CountryCode": "AU",
                "IsDemoCompany": False,
                "OrganisationStatus": "ACTIVE",
                "RegistrationNumber": "12 345 678 901",
                "TaxNumber": "12 345 678 901",
                "FinancialYearEndDay": 30,
                "FinancialYearEndMonth": 6,
                "SalesTaxBasis": "ACCRUALS",
                "SalesTaxPeriod": "QUARTERLY",
                "DefaultSalesTax": "OUTPUT",
                "DefaultPurchasesTax": "INPUT",
                "PeriodLockDate": "2024-03-31",
                "EndOfYearLockDate": "2023-06-30",
                "CreatedDateUTC": "2020-01-15T00:00:00",
                "Timezone": "AUSEASTERNSTANDARDTIME",
                "OrganisationEntityType": "COMPANY",
                "Edition": "BUSINESS"
            }
            
            return True, org_info
            
        except Exception as e:
            return False, f"Error retrieving Xero organization info: {str(e)}"

