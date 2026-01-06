"""
Smart Application Pre-Fill Service for GrantThrive Platform
Enables auto-population of applications using previous submissions and organization profiles
"""

import json
from datetime import datetime
from typing import Dict, List, Optional

class ApplicationPrefillService:
    """
    Service for managing application pre-fill functionality
    """
    
    def __init__(self):
        # In-memory storage for demo (in production, use database)
        self.organization_profiles = {}
        self.application_history = {}
        self.field_mappings = self._initialize_field_mappings()
        
    def _initialize_field_mappings(self):
        """
        Initialize field mappings for different grant types
        """
        return {
            'organization_info': {
                'organization_name': ['org_name', 'company_name', 'entity_name'],
                'abn': ['abn_number', 'business_number', 'tax_id'],
                'address': ['street_address', 'postal_address', 'mailing_address'],
                'city': ['suburb', 'locality', 'town'],
                'state': ['state_territory', 'province'],
                'postcode': ['postal_code', 'zip_code'],
                'phone': ['contact_phone', 'telephone', 'phone_number'],
                'email': ['contact_email', 'email_address', 'primary_email'],
                'website': ['website_url', 'web_address', 'homepage'],
                'organization_type': ['entity_type', 'business_type', 'org_category'],
                'incorporation_date': ['established_date', 'founded_date', 'registration_date'],
                'employee_count': ['staff_count', 'workforce_size', 'team_size']
            },
            'contact_info': {
                'primary_contact_name': ['contact_person', 'main_contact', 'representative'],
                'primary_contact_title': ['contact_title', 'position', 'role'],
                'primary_contact_phone': ['contact_mobile', 'direct_phone'],
                'primary_contact_email': ['contact_direct_email', 'personal_email'],
                'secondary_contact_name': ['backup_contact', 'alternate_contact'],
                'secondary_contact_title': ['backup_title', 'alternate_title'],
                'secondary_contact_phone': ['backup_phone', 'alternate_phone'],
                'secondary_contact_email': ['backup_email', 'alternate_email']
            },
            'financial_info': {
                'annual_revenue': ['yearly_revenue', 'annual_turnover', 'total_income'],
                'annual_expenses': ['yearly_expenses', 'operating_costs', 'total_expenses'],
                'current_funding': ['existing_grants', 'current_support', 'other_funding'],
                'bank_name': ['financial_institution', 'banking_partner'],
                'bank_bsb': ['bsb_number', 'routing_number'],
                'bank_account': ['account_number', 'bank_account_number'],
                'account_name': ['account_holder', 'beneficiary_name']
            },
            'project_info': {
                'project_title': ['program_name', 'initiative_title', 'project_name'],
                'project_description': ['program_description', 'initiative_summary'],
                'project_objectives': ['goals', 'aims', 'intended_outcomes'],
                'target_audience': ['beneficiaries', 'participants', 'target_group'],
                'project_location': ['delivery_location', 'service_area', 'geographic_scope'],
                'project_duration': ['timeline', 'project_length', 'implementation_period'],
                'requested_amount': ['funding_request', 'grant_amount', 'budget_total'],
                'matching_funds': ['co_contribution', 'organization_contribution', 'self_funding']
            }
        }
    
    def create_organization_profile(self, user_id: str, organization_data: Dict) -> Dict:
        """
        Create or update organization profile for pre-fill
        
        Args:
            user_id (str): User identifier
            organization_data (dict): Organization information
            
        Returns:
            dict: Profile creation result
        """
        try:
            profile = {
                'user_id': user_id,
                'organization_data': organization_data,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'application_count': 0,
                'success_rate': 0.0,
                'last_used': None
            }
            
            self.organization_profiles[user_id] = profile
            
            return {
                'success': True,
                'profile_id': user_id,
                'message': 'Organization profile created successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_organization_profile(self, user_id: str) -> Optional[Dict]:
        """
        Get organization profile for user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict or None: Organization profile
        """
        return self.organization_profiles.get(user_id)
    
    def update_organization_profile(self, user_id: str, updates: Dict) -> Dict:
        """
        Update organization profile
        
        Args:
            user_id (str): User identifier
            updates (dict): Profile updates
            
        Returns:
            dict: Update result
        """
        try:
            if user_id not in self.organization_profiles:
                return {
                    'success': False,
                    'error': 'Organization profile not found'
                }
            
            profile = self.organization_profiles[user_id]
            profile['organization_data'].update(updates)
            profile['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'message': 'Organization profile updated successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def save_application_data(self, user_id: str, application_data: Dict) -> Dict:
        """
        Save application data for future pre-fill
        
        Args:
            user_id (str): User identifier
            application_data (dict): Application information
            
        Returns:
            dict: Save result
        """
        try:
            application_id = application_data.get('application_id', f"app_{int(datetime.now().timestamp())}")
            
            if user_id not in self.application_history:
                self.application_history[user_id] = []
            
            # Store application data
            stored_application = {
                'application_id': application_id,
                'grant_type': application_data.get('grant_type', 'general'),
                'grant_title': application_data.get('grant_title', 'Unknown Grant'),
                'application_data': application_data,
                'submitted_at': datetime.now().isoformat(),
                'status': application_data.get('status', 'submitted'),
                'success': application_data.get('success', False)
            }
            
            self.application_history[user_id].append(stored_application)
            
            # Update organization profile statistics
            if user_id in self.organization_profiles:
                profile = self.organization_profiles[user_id]
                profile['application_count'] += 1
                profile['last_used'] = datetime.now().isoformat()
                
                # Calculate success rate
                successful_apps = sum(1 for app in self.application_history[user_id] if app.get('success', False))
                profile['success_rate'] = (successful_apps / profile['application_count']) * 100
            
            return {
                'success': True,
                'application_id': application_id,
                'message': 'Application data saved for future pre-fill'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_prefill_suggestions(self, user_id: str, grant_type: str = None) -> Dict:
        """
        Get pre-fill suggestions for new application
        
        Args:
            user_id (str): User identifier
            grant_type (str, optional): Type of grant for targeted suggestions
            
        Returns:
            dict: Pre-fill suggestions
        """
        try:
            suggestions = {
                'organization_info': {},
                'contact_info': {},
                'financial_info': {},
                'project_info': {},
                'previous_applications': [],
                'confidence_scores': {},
                'data_sources': {}
            }
            
            # Get organization profile data
            profile = self.get_organization_profile(user_id)
            if profile:
                org_data = profile['organization_data']
                suggestions['organization_info'] = self._extract_organization_fields(org_data)
                suggestions['data_sources']['organization_profile'] = True
            
            # Get data from previous applications
            if user_id in self.application_history:
                applications = self.application_history[user_id]
                
                # Filter by grant type if specified
                if grant_type:
                    relevant_apps = [app for app in applications if app.get('grant_type') == grant_type]
                else:
                    relevant_apps = applications
                
                if relevant_apps:
                    # Get most recent successful application
                    successful_apps = [app for app in relevant_apps if app.get('success', False)]
                    if successful_apps:
                        latest_successful = max(successful_apps, key=lambda x: x['submitted_at'])
                        suggestions.update(self._extract_application_fields(latest_successful['application_data']))
                        suggestions['data_sources']['successful_application'] = latest_successful['application_id']
                    
                    # Get most recent application regardless of success
                    latest_app = max(relevant_apps, key=lambda x: x['submitted_at'])
                    if not successful_apps or latest_app['application_id'] != suggestions['data_sources'].get('successful_application'):
                        recent_suggestions = self._extract_application_fields(latest_app['application_data'])
                        # Merge with existing suggestions, prioritizing successful application data
                        for category, fields in recent_suggestions.items():
                            if category in suggestions and isinstance(suggestions[category], dict):
                                for field, value in fields.items():
                                    if field not in suggestions[category]:
                                        suggestions[category][field] = value
                        suggestions['data_sources']['recent_application'] = latest_app['application_id']
                
                # Add previous applications list
                suggestions['previous_applications'] = [
                    {
                        'application_id': app['application_id'],
                        'grant_title': app['grant_title'],
                        'grant_type': app['grant_type'],
                        'submitted_at': app['submitted_at'],
                        'status': app['status'],
                        'success': app.get('success', False)
                    }
                    for app in applications[-5:]  # Last 5 applications
                ]
            
            # Calculate confidence scores
            suggestions['confidence_scores'] = self._calculate_confidence_scores(suggestions)
            
            return {
                'success': True,
                'suggestions': suggestions,
                'user_id': user_id,
                'grant_type': grant_type
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_organization_fields(self, org_data: Dict) -> Dict:
        """
        Extract organization fields for pre-fill
        """
        extracted = {}
        
        for standard_field, aliases in self.field_mappings['organization_info'].items():
            # Check for exact match first
            if standard_field in org_data:
                extracted[standard_field] = org_data[standard_field]
            else:
                # Check aliases
                for alias in aliases:
                    if alias in org_data:
                        extracted[standard_field] = org_data[alias]
                        break
        
        return extracted
    
    def _extract_application_fields(self, app_data: Dict) -> Dict:
        """
        Extract application fields for pre-fill
        """
        extracted = {
            'organization_info': {},
            'contact_info': {},
            'financial_info': {},
            'project_info': {}
        }
        
        for category, field_mappings in self.field_mappings.items():
            for standard_field, aliases in field_mappings.items():
                # Check for exact match first
                if standard_field in app_data:
                    extracted[category][standard_field] = app_data[standard_field]
                else:
                    # Check aliases
                    for alias in aliases:
                        if alias in app_data:
                            extracted[category][standard_field] = app_data[alias]
                            break
        
        return extracted
    
    def _calculate_confidence_scores(self, suggestions: Dict) -> Dict:
        """
        Calculate confidence scores for pre-fill suggestions
        """
        scores = {}
        
        for category, fields in suggestions.items():
            if isinstance(fields, dict) and fields:
                # Base confidence on data sources and field completeness
                base_score = 0.5
                
                if suggestions['data_sources'].get('organization_profile'):
                    base_score += 0.2
                
                if suggestions['data_sources'].get('successful_application'):
                    base_score += 0.3
                elif suggestions['data_sources'].get('recent_application'):
                    base_score += 0.2
                
                # Adjust based on field completeness
                field_count = len(fields)
                max_fields = len(self.field_mappings.get(category, {}))
                if max_fields > 0:
                    completeness_bonus = (field_count / max_fields) * 0.2
                    base_score += completeness_bonus
                
                scores[category] = min(base_score, 1.0)
        
        return scores
    
    def apply_prefill_data(self, user_id: str, application_form: Dict, prefill_options: Dict = None) -> Dict:
        """
        Apply pre-fill data to application form
        
        Args:
            user_id (str): User identifier
            application_form (dict): Empty or partially filled application form
            prefill_options (dict, optional): Specific pre-fill preferences
            
        Returns:
            dict: Pre-filled application form
        """
        try:
            if not prefill_options:
                prefill_options = {
                    'use_organization_profile': True,
                    'use_previous_applications': True,
                    'overwrite_existing': False,
                    'grant_type': application_form.get('grant_type')
                }
            
            # Get pre-fill suggestions
            suggestions_result = self.get_prefill_suggestions(
                user_id, 
                prefill_options.get('grant_type')
            )
            
            if not suggestions_result['success']:
                return suggestions_result
            
            suggestions = suggestions_result['suggestions']
            prefilled_form = application_form.copy()
            applied_fields = []
            
            # Apply pre-fill data
            for category, fields in suggestions.items():
                if isinstance(fields, dict):
                    for field, value in fields.items():
                        # Check if field exists in form and should be filled
                        if self._should_prefill_field(prefilled_form, field, value, prefill_options):
                            prefilled_form[field] = value
                            applied_fields.append({
                                'field': field,
                                'category': category,
                                'value': value,
                                'confidence': suggestions['confidence_scores'].get(category, 0.5)
                            })
            
            return {
                'success': True,
                'prefilled_form': prefilled_form,
                'applied_fields': applied_fields,
                'suggestions_used': suggestions['data_sources'],
                'confidence_scores': suggestions['confidence_scores']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _should_prefill_field(self, form: Dict, field: str, value: any, options: Dict) -> bool:
        """
        Determine if a field should be pre-filled
        """
        # Don't prefill if field already has a value and overwrite is disabled
        if field in form and form[field] and not options.get('overwrite_existing', False):
            return False
        
        # Don't prefill empty or None values
        if value is None or value == '':
            return False
        
        # Field is eligible for pre-fill
        return True
    
    def get_prefill_statistics(self, user_id: str) -> Dict:
        """
        Get pre-fill usage statistics for user
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: Pre-fill statistics
        """
        try:
            profile = self.get_organization_profile(user_id)
            applications = self.application_history.get(user_id, [])
            
            stats = {
                'profile_exists': profile is not None,
                'total_applications': len(applications),
                'successful_applications': sum(1 for app in applications if app.get('success', False)),
                'success_rate': 0.0,
                'last_application': None,
                'prefill_usage': {
                    'organization_profile_used': 0,
                    'previous_application_used': 0,
                    'average_fields_prefilled': 0
                },
                'data_quality': {
                    'organization_completeness': 0.0,
                    'contact_completeness': 0.0,
                    'financial_completeness': 0.0
                }
            }
            
            if applications:
                stats['success_rate'] = (stats['successful_applications'] / stats['total_applications']) * 100
                stats['last_application'] = applications[-1]['submitted_at']
            
            if profile:
                org_data = profile['organization_data']
                
                # Calculate data completeness
                for category in ['organization_info', 'contact_info', 'financial_info']:
                    if category in self.field_mappings:
                        total_fields = len(self.field_mappings[category])
                        filled_fields = sum(1 for field in self.field_mappings[category] 
                                          if field in org_data and org_data[field])
                        completeness = (filled_fields / total_fields) * 100 if total_fields > 0 else 0
                        
                        if category == 'organization_info':
                            stats['data_quality']['organization_completeness'] = completeness
                        elif category == 'contact_info':
                            stats['data_quality']['contact_completeness'] = completeness
                        elif category == 'financial_info':
                            stats['data_quality']['financial_completeness'] = completeness
            
            return {
                'success': True,
                'statistics': stats
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def export_organization_profile(self, user_id: str) -> Dict:
        """
        Export organization profile for backup or transfer
        
        Args:
            user_id (str): User identifier
            
        Returns:
            dict: Exported profile data
        """
        try:
            profile = self.get_organization_profile(user_id)
            
            if not profile:
                return {
                    'success': False,
                    'error': 'Organization profile not found'
                }
            
            export_data = {
                'profile': profile,
                'applications': self.application_history.get(user_id, []),
                'export_date': datetime.now().isoformat(),
                'version': '1.0'
            }
            
            return {
                'success': True,
                'export_data': export_data
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def import_organization_profile(self, user_id: str, import_data: Dict) -> Dict:
        """
        Import organization profile from backup
        
        Args:
            user_id (str): User identifier
            import_data (dict): Imported profile data
            
        Returns:
            dict: Import result
        """
        try:
            if 'profile' not in import_data:
                return {
                    'success': False,
                    'error': 'Invalid import data format'
                }
            
            # Import profile
            profile = import_data['profile']
            profile['user_id'] = user_id  # Ensure correct user ID
            profile['updated_at'] = datetime.now().isoformat()
            
            self.organization_profiles[user_id] = profile
            
            # Import applications if available
            if 'applications' in import_data:
                self.application_history[user_id] = import_data['applications']
            
            return {
                'success': True,
                'message': 'Organization profile imported successfully'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

