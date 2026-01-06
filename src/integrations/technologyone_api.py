"""
TechnologyOne API Integration for GrantThrive Platform
Handles integration with TechnologyOne Ci Anywhere platform
Popular enterprise solution for Australian councils and government agencies
"""

import os
import requests
from datetime import datetime, timedelta
from .base_connector import BaseConnector

class TechnologyOneConnector(BaseConnector):
    """
    TechnologyOne API connector for syncing grant data
    with TechnologyOne Ci Anywhere platform for comprehensive council management.
    """
    
    def __init__(self):
        super().__init__('TECHNOLOGYONE')
        self.instance_url = self._get_credential('INSTANCE_URL')
        self.access_token = None
        self.refresh_token = self._get_credential('REFRESH_TOKEN')
        self.client_id = self.api_key
        self.client_secret = self.api_secret
        
    def authenticate(self):
        """
        Authenticate with TechnologyOne using OAuth 2.0
        Returns access token for API calls
        """
        auth_url = f"{self.instance_url}/oauth/token"
        
        auth_data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'api'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            response = requests.post(auth_url, data=auth_data, headers=headers)
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result.get('access_token')
                return True, "Successfully authenticated with TechnologyOne"
            else:
                return False, f"TechnologyOne authentication failed: {response.text}"
        except Exception as e:
            return False, f"TechnologyOne authentication error: {str(e)}"
    
    def create_customer(self, organization_data):
        """
        Create a customer record in TechnologyOne for grant recipient
        
        Args:
            organization_data (dict): Organization information
            
        Returns:
            tuple: (success: bool, customer_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare TechnologyOne customer data
        customer_data = {
            "customerCode": organization_data.get('abn', '').replace(' ', '') or f"GRANT{datetime.now().strftime('%Y%m%d')}",
            "customerName": organization_data.get('organization_name', ''),
            "customerType": "GRANT_RECIPIENT",
            "status": "ACTIVE",
            "addresses": [{
                "addressType": "PRIMARY",
                "streetAddress": organization_data.get('address_line1', ''),
                "streetAddress2": organization_data.get('address_line2', ''),
                "suburb": organization_data.get('city', ''),
                "state": organization_data.get('state', ''),
                "postcode": organization_data.get('postal_code', ''),
                "country": organization_data.get('country', 'Australia')
            }],
            "contacts": [{
                "contactType": "PRIMARY",
                "firstName": organization_data.get('contact_firstname', ''),
                "lastName": organization_data.get('contact_lastname', ''),
                "email": organization_data.get('email', ''),
                "phone": organization_data.get('phone', ''),
                "position": organization_data.get('contact_position', '')
            }],
            "customFields": {
                "ABN": organization_data.get('abn', ''),
                "GrantProgram": organization_data.get('grant_program', ''),
                "OrganizationType": organization_data.get('organization_type', ''),
                "CreatedVia": "GrantThrive Platform"
            },
            "notes": f"Grant recipient organization created via GrantThrive on {datetime.now().strftime('%d/%m/%Y')}"
        }
        
        try:
            print(f"Creating TechnologyOne customer: {customer_data}")
            
            # Simulated customer creation
            customer_id = f"t1_cust_{organization_data.get('organization_name', 'unknown').replace(' ', '_').lower()}"
            
            return True, customer_id
            
        except Exception as e:
            return False, f"TechnologyOne customer creation error: {str(e)}"
    
    def create_grant_project(self, grant_data):
        """
        Create a project record in TechnologyOne for grant tracking
        
        Args:
            grant_data (dict): Grant information
            
        Returns:
            tuple: (success: bool, project_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare TechnologyOne project data
        project_data = {
            "projectCode": f"GRANT-{grant_data.get('grant_id', datetime.now().strftime('%Y%m%d'))}",
            "projectName": grant_data.get('grant_title', 'Grant Project'),
            "projectType": "GRANT_FUNDING",
            "status": self._map_status_to_project_status(grant_data.get('status', 'draft')),
            "startDate": grant_data.get('start_date', datetime.now().strftime('%Y-%m-%d')),
            "endDate": grant_data.get('end_date', (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')),
            "budget": {
                "totalBudget": grant_data.get('funding_amount', 0),
                "currency": "AUD",
                "budgetType": "GRANT_ALLOCATION"
            },
            "description": grant_data.get('description', ''),
            "projectManager": {
                "employeeId": grant_data.get('project_manager_id', 'GRANT_ADMIN'),
                "name": grant_data.get('project_manager_name', 'Grant Administrator')
            },
            "customFields": {
                "GrantProgram": grant_data.get('grant_program', ''),
                "FundingSource": grant_data.get('funding_source', 'Council'),
                "GrantCategory": grant_data.get('category', ''),
                "RecipientOrganization": grant_data.get('organization', {}).get('organization_name', ''),
                "ApplicationDate": grant_data.get('application_date', datetime.now().strftime('%Y-%m-%d'))
            },
            "milestones": self._create_grant_milestones(grant_data),
            "stakeholders": [{
                "stakeholderType": "RECIPIENT",
                "organizationName": grant_data.get('organization', {}).get('organization_name', ''),
                "contactEmail": grant_data.get('organization', {}).get('email', ''),
                "role": "Grant Recipient"
            }]
        }
        
        try:
            print(f"Creating TechnologyOne grant project: {project_data}")
            
            # Simulated project creation
            project_id = project_data["projectCode"]
            
            return True, project_id
            
        except Exception as e:
            return False, f"TechnologyOne grant project creation error: {str(e)}"
    
    def create_financial_transaction(self, transaction_data):
        """
        Create a financial transaction in TechnologyOne
        
        Args:
            transaction_data (dict): Transaction information
            
        Returns:
            tuple: (success: bool, transaction_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare TechnologyOne financial transaction
        financial_transaction = {
            "transactionType": transaction_data.get('type', 'GRANT_PAYMENT'),
            "transactionDate": transaction_data.get('date', datetime.now().strftime('%Y-%m-%d')),
            "amount": transaction_data.get('amount', 0),
            "currency": "AUD",
            "description": transaction_data.get('description', 'Grant-related transaction'),
            "reference": transaction_data.get('reference', f"GRANT-{datetime.now().strftime('%Y%m%d')}"),
            "accountingPeriod": transaction_data.get('period', datetime.now().strftime('%Y-%m')),
            "chartOfAccounts": {
                "accountCode": transaction_data.get('account_code', '4-1000'),
                "accountName": transaction_data.get('account_name', 'Grant Income'),
                "accountType": transaction_data.get('account_type', 'INCOME')
            },
            "costCenter": transaction_data.get('cost_center', 'GRANTS'),
            "projectCode": transaction_data.get('project_code', ''),
            "gstAmount": transaction_data.get('gst_amount', 0),
            "gstCode": transaction_data.get('gst_code', 'FRE'),  # GST Free for grants
            "approvalStatus": "APPROVED",
            "createdBy": "GrantThrive System",
            "customFields": {
                "GrantId": transaction_data.get('grant_id', ''),
                "RecipientOrganization": transaction_data.get('recipient', ''),
                "TransactionSource": "GrantThrive Platform"
            }
        }
        
        try:
            print(f"Creating TechnologyOne financial transaction: {financial_transaction}")
            
            # Simulated transaction creation
            transaction_id = f"t1_txn_{transaction_data.get('reference', 'unknown')}"
            
            return True, transaction_id
            
        except Exception as e:
            return False, f"TechnologyOne financial transaction error: {str(e)}"
    
    def create_workflow_task(self, task_data):
        """
        Create a workflow task in TechnologyOne for grant processing
        
        Args:
            task_data (dict): Task information
            
        Returns:
            tuple: (success: bool, task_id: str or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Prepare TechnologyOne workflow task
        workflow_task = {
            "taskType": task_data.get('type', 'GRANT_REVIEW'),
            "taskTitle": task_data.get('title', 'Grant Application Review'),
            "taskDescription": task_data.get('description', 'Review grant application and make decision'),
            "priority": task_data.get('priority', 'MEDIUM'),
            "status": "PENDING",
            "assignedTo": {
                "employeeId": task_data.get('assignee_id', 'GRANT_OFFICER'),
                "name": task_data.get('assignee_name', 'Grant Officer'),
                "department": task_data.get('department', 'Community Services')
            },
            "dueDate": task_data.get('due_date', (datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d')),
            "createdDate": datetime.now().strftime('%Y-%m-%d'),
            "relatedRecords": [{
                "recordType": "GRANT_APPLICATION",
                "recordId": task_data.get('grant_id', ''),
                "recordTitle": task_data.get('grant_title', '')
            }],
            "workflowStage": task_data.get('stage', 'INITIAL_REVIEW'),
            "customFields": {
                "GrantAmount": task_data.get('grant_amount', 0),
                "ApplicantOrganization": task_data.get('applicant', ''),
                "GrantCategory": task_data.get('category', ''),
                "ReviewCriteria": task_data.get('criteria', [])
            },
            "attachments": task_data.get('attachments', [])
        }
        
        try:
            print(f"Creating TechnologyOne workflow task: {workflow_task}")
            
            # Simulated task creation
            task_id = f"t1_task_{task_data.get('grant_id', 'unknown')}"
            
            return True, task_id
            
        except Exception as e:
            return False, f"TechnologyOne workflow task creation error: {str(e)}"
    
    def generate_compliance_report(self, start_date, end_date):
        """
        Generate compliance and audit report for grant activities
        
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
            # Simulated comprehensive compliance report
            report_data = {
                "report_period": f"{start_date} to {end_date}",
                "generated_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "council_name": "Mount Isa City Council",
                "total_grants_processed": 28,
                "total_funding_allocated": 325000.00,
                "compliance_metrics": {
                    "applications_within_deadline": 26,
                    "applications_late": 2,
                    "compliance_rate": 92.86,
                    "average_processing_time_days": 18.5,
                    "appeals_received": 1,
                    "appeals_upheld": 0
                },
                "financial_summary": {
                    "total_budget_allocated": 400000.00,
                    "total_grants_awarded": 325000.00,
                    "budget_utilization_percent": 81.25,
                    "administration_costs": 22500.00,
                    "cost_per_grant_processed": 803.57
                },
                "grant_categories": {
                    "Community Development": {
                        "applications": 8,
                        "approved": 7,
                        "total_funding": 125000.00,
                        "average_amount": 17857.14
                    },
                    "Youth Programs": {
                        "applications": 6,
                        "approved": 5,
                        "total_funding": 85000.00,
                        "average_amount": 17000.00
                    },
                    "Environmental": {
                        "applications": 7,
                        "approved": 6,
                        "total_funding": 75000.00,
                        "average_amount": 12500.00
                    },
                    "Arts & Culture": {
                        "applications": 7,
                        "approved": 6,
                        "total_funding": 40000.00,
                        "average_amount": 6666.67
                    }
                },
                "audit_trail": {
                    "total_actions_logged": 156,
                    "user_actions": 134,
                    "system_actions": 22,
                    "data_integrity_checks": "PASSED",
                    "security_compliance": "COMPLIANT"
                },
                "recommendations": [
                    "Consider increasing budget allocation for Community Development grants due to high demand",
                    "Implement automated reminders for application deadlines to reduce late submissions",
                    "Review processing times for Environmental grants to improve efficiency"
                ]
            }
            
            return True, report_data
            
        except Exception as e:
            return False, f"Error generating TechnologyOne compliance report: {str(e)}"
    
    def sync_complete_grant_lifecycle(self, grant_data):
        """
        Complete synchronization of grant lifecycle to TechnologyOne
        
        Args:
            grant_data (dict): Complete grant information
            
        Returns:
            tuple: (success: bool, sync_summary: dict or error_message: str)
        """
        try:
            sync_results = {}
            
            # Create customer for organization
            customer_success, customer_id = self.create_customer(grant_data.get('organization', {}))
            sync_results['customer'] = {'success': customer_success, 'id': customer_id}
            
            # Create project for grant tracking
            project_success, project_id = self.create_grant_project(grant_data)
            sync_results['project'] = {'success': project_success, 'id': project_id}
            
            # Create financial transaction for grant funding
            if grant_data.get('funding_amount'):
                transaction_data = {
                    'type': 'GRANT_PAYMENT',
                    'amount': grant_data['funding_amount'],
                    'description': f"Grant funding: {grant_data.get('grant_title')}",
                    'reference': f"GRANT-{grant_data.get('grant_id')}",
                    'project_code': project_id,
                    'grant_id': grant_data.get('grant_id'),
                    'recipient': grant_data.get('organization', {}).get('organization_name')
                }
                transaction_success, transaction_id = self.create_financial_transaction(transaction_data)
                sync_results['transaction'] = {'success': transaction_success, 'id': transaction_id}
            
            # Create workflow task for ongoing management
            task_data = {
                'type': 'GRANT_MONITORING',
                'title': f"Monitor Grant: {grant_data.get('grant_title')}",
                'description': f"Monitor progress and compliance for grant {grant_data.get('grant_id')}",
                'grant_id': grant_data.get('grant_id'),
                'grant_title': grant_data.get('grant_title'),
                'grant_amount': grant_data.get('funding_amount'),
                'applicant': grant_data.get('organization', {}).get('organization_name'),
                'category': grant_data.get('category')
            }
            task_success, task_id = self.create_workflow_task(task_data)
            sync_results['workflow_task'] = {'success': task_success, 'id': task_id}
            
            # Determine overall success
            overall_success = customer_success and project_success
            
            if overall_success:
                sync_summary = {
                    "status": "success",
                    "grant_id": grant_data.get('grant_id'),
                    "organization": grant_data.get('organization', {}).get('organization_name'),
                    "amount": grant_data.get('funding_amount'),
                    "technologyone_records": sync_results,
                    "sync_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "next_actions": [
                        "Monitor project milestones",
                        "Track financial transactions",
                        "Ensure compliance reporting"
                    ]
                }
                return True, sync_summary
            else:
                return False, f"Partial sync failure: {sync_results}"
                
        except Exception as e:
            return False, f"TechnologyOne complete grant lifecycle sync error: {str(e)}"
    
    def _map_status_to_project_status(self, status):
        """
        Map GrantThrive status to TechnologyOne project status
        """
        status_mapping = {
            'draft': 'PLANNING',
            'submitted': 'ACTIVE',
            'under_review': 'ACTIVE',
            'approved': 'ACTIVE',
            'rejected': 'CANCELLED',
            'completed': 'COMPLETED',
            'pending': 'ON_HOLD'
        }
        return status_mapping.get(status.lower(), 'PLANNING')
    
    def _create_grant_milestones(self, grant_data):
        """
        Create standard milestones for grant projects
        """
        milestones = [
            {
                "milestoneId": "M001",
                "milestoneName": "Grant Application Approved",
                "description": "Grant application has been approved and funding allocated",
                "targetDate": grant_data.get('approval_date', datetime.now().strftime('%Y-%m-%d')),
                "status": "COMPLETED" if grant_data.get('status') == 'approved' else "PENDING"
            },
            {
                "milestoneId": "M002", 
                "milestoneName": "Project Commencement",
                "description": "Grant recipient begins project implementation",
                "targetDate": grant_data.get('start_date', (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d')),
                "status": "PENDING"
            },
            {
                "milestoneId": "M003",
                "milestoneName": "Mid-Project Review",
                "description": "Review project progress and compliance",
                "targetDate": grant_data.get('mid_review_date', (datetime.now() + timedelta(days=180)).strftime('%Y-%m-%d')),
                "status": "PENDING"
            },
            {
                "milestoneId": "M004",
                "milestoneName": "Project Completion",
                "description": "Grant project completed and final report submitted",
                "targetDate": grant_data.get('end_date', (datetime.now() + timedelta(days=365)).strftime('%Y-%m-%d')),
                "status": "PENDING"
            }
        ]
        return milestones

