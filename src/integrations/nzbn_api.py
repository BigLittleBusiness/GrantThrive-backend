"""
New Zealand Business Number (NZBN) API Integration for GrantThrive Platform
Handles real-time NZBN validation and business verification
Official New Zealand Government business registry integration
"""

import os
import requests
from datetime import datetime
from .base_connector import BaseConnector

class NZBNConnector(BaseConnector):
    """
    New Zealand Business Number API connector for real-time NZBN validation
    and business verification using official government data.
    """
    
    def __init__(self):
        super().__init__('NZBN')
        self.base_url = "https://api.business.govt.nz/gateway/nzbn/v5"
        self.access_token = None
        self.client_id = self.api_key
        self.client_secret = self.api_secret
        
    def authenticate(self):
        """
        Authenticate with NZBN API using OAuth 2.0
        Returns access token for API calls
        """
        auth_url = "https://api.business.govt.nz/gateway/oauth/token"
        
        auth_data = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'nzbn'
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        try:
            response = requests.post(auth_url, data=auth_data, headers=headers, timeout=10)
            if response.status_code == 200:
                auth_result = response.json()
                self.access_token = auth_result.get('access_token')
                return True, "Successfully authenticated with NZBN API"
            else:
                return False, f"NZBN authentication failed: {response.text}"
        except Exception as e:
            return False, f"NZBN authentication error: {str(e)}"
    
    def validate_nzbn(self, nzbn):
        """
        Validate NZBN format using New Zealand algorithm
        
        Args:
            nzbn (str): NZBN to validate
            
        Returns:
            tuple: (is_valid: bool, formatted_nzbn: str or error_message: str)
        """
        try:
            # Remove spaces and non-numeric characters
            clean_nzbn = ''.join(filter(str.isdigit, nzbn))
            
            # Check length (NZBN is 13 digits)
            if len(clean_nzbn) != 13:
                return False, "NZBN must be 13 digits"
            
            # NZBN checksum validation using modulus 97 algorithm
            # Take first 11 digits, multiply by 100, divide by 97, remainder should equal last 2 digits
            first_eleven = clean_nzbn[:11]
            check_digits = clean_nzbn[11:13]
            
            # Calculate check digits
            number_to_check = int(first_eleven + '00')
            remainder = number_to_check % 97
            calculated_check = 98 - remainder
            
            if calculated_check == int(check_digits):
                # Format as XXXX-XXXX-XXXXX
                formatted = f"{clean_nzbn[:4]}-{clean_nzbn[4:8]}-{clean_nzbn[8:13]}"
                return True, formatted
            else:
                return False, "Invalid NZBN checksum"
                
        except Exception as e:
            return False, f"NZBN validation error: {str(e)}"
    
    def lookup_nzbn_details(self, nzbn):
        """
        Look up business details from NZBN register
        
        Args:
            nzbn (str): NZBN to look up
            
        Returns:
            tuple: (success: bool, business_data: dict or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        # Validate NZBN format first
        is_valid, formatted_nzbn = self.validate_nzbn(nzbn)
        if not is_valid:
            return False, formatted_nzbn
        
        try:
            # Clean NZBN for API call
            clean_nzbn = ''.join(filter(str.isdigit, nzbn))
            
            url = f"{self.base_url}/entities/{clean_nzbn}"
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                business_data = {
                    'nzbn': formatted_nzbn,
                    'entity_name': data.get('entityName', ''),
                    'entity_type': data.get('entityTypeDescription', ''),
                    'entity_status': data.get('entityStatusDescription', ''),
                    'registration_date': data.get('registrationDate', ''),
                    'gst_number': data.get('gstNumber', ''),
                    'trading_names': [],
                    'addresses': [],
                    'directors': [],
                    'industry_classifications': [],
                    'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Extract trading names
                if 'tradingNames' in data:
                    for trading_name in data['tradingNames']:
                        business_data['trading_names'].append({
                            'name': trading_name.get('name', ''),
                            'start_date': trading_name.get('startDate', ''),
                            'end_date': trading_name.get('endDate', '')
                        })
                
                # Extract addresses
                if 'addresses' in data:
                    for address in data['addresses']:
                        business_data['addresses'].append({
                            'address_type': address.get('addressType', ''),
                            'address_line1': address.get('addressLine1', ''),
                            'address_line2': address.get('addressLine2', ''),
                            'suburb': address.get('suburb', ''),
                            'city': address.get('city', ''),
                            'region': address.get('region', ''),
                            'postcode': address.get('postcode', ''),
                            'country': address.get('countryDescription', 'New Zealand')
                        })
                
                # Extract directors/officers
                if 'roles' in data:
                    for role in data['roles']:
                        if role.get('roleType') in ['Director', 'Shareholder', 'Officer']:
                            business_data['directors'].append({
                                'name': role.get('fullName', ''),
                                'role_type': role.get('roleType', ''),
                                'appointment_date': role.get('appointmentDate', ''),
                                'cessation_date': role.get('cessationDate', '')
                            })
                
                # Extract industry classifications
                if 'industryClassifications' in data:
                    for classification in data['industryClassifications']:
                        business_data['industry_classifications'].append({
                            'code': classification.get('classificationCode', ''),
                            'description': classification.get('classificationDescription', '')
                        })
                
                return True, business_data
                
            elif response.status_code == 404:
                return False, "NZBN not found in register"
            else:
                return False, f"NZBN API error: {response.status_code} - {response.text}"
                
        except Exception as e:
            return False, f"NZBN lookup error: {str(e)}"
    
    def search_business_name(self, business_name):
        """
        Search for businesses by name in NZBN register
        
        Args:
            business_name (str): Business name to search
            
        Returns:
            tuple: (success: bool, search_results: list or error_message: str)
        """
        if not self.access_token:
            auth_success, auth_message = self.authenticate()
            if not auth_success:
                return False, auth_message
        
        try:
            url = f"{self.base_url}/entities"
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json'
            }
            
            params = {
                'entity-name': business_name,
                'limit': 20
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                search_results = []
                if 'items' in data:
                    for item in data['items']:
                        result = {
                            'nzbn': item.get('nzbn', ''),
                            'entity_name': item.get('entityName', ''),
                            'entity_type': item.get('entityTypeDescription', ''),
                            'entity_status': item.get('entityStatusDescription', ''),
                            'registration_date': item.get('registrationDate', ''),
                            'addresses': []
                        }
                        
                        # Extract primary address
                        if 'addresses' in item:
                            for address in item['addresses']:
                                if address.get('addressType') == 'Registered Office':
                                    result['addresses'].append({
                                        'suburb': address.get('suburb', ''),
                                        'city': address.get('city', ''),
                                        'region': address.get('region', ''),
                                        'postcode': address.get('postcode', '')
                                    })
                                    break
                        
                        search_results.append(result)
                
                return True, search_results
            else:
                return False, f"NZBN search error: {response.status_code}"
                
        except Exception as e:
            return False, f"NZBN search error: {str(e)}"
    
    def verify_grant_eligibility(self, nzbn):
        """
        Verify if business is eligible for grants based on NZBN data
        
        Args:
            nzbn (str): NZBN to verify
            
        Returns:
            tuple: (success: bool, eligibility_data: dict or error_message: str)
        """
        # Get business details first
        success, business_data = self.lookup_nzbn_details(nzbn)
        
        if not success:
            return False, business_data
        
        try:
            eligibility_data = {
                'nzbn': business_data['nzbn'],
                'entity_name': business_data['entity_name'],
                'is_eligible': True,
                'eligibility_factors': [],
                'warnings': [],
                'recommendations': []
            }
            
            # Check entity status
            entity_status = business_data['entity_status'].upper()
            if 'REGISTERED' in entity_status or 'ACTIVE' in entity_status:
                eligibility_data['eligibility_factors'].append(f"Entity status: {business_data['entity_status']}")
            else:
                eligibility_data['is_eligible'] = False
                eligibility_data['warnings'].append(f"Entity status is {business_data['entity_status']}")
            
            # Check entity type
            entity_type = business_data['entity_type'].upper()
            if 'COMPANY' in entity_type:
                eligibility_data['eligibility_factors'].append("Registered company structure")
            elif 'TRUST' in entity_type:
                eligibility_data['eligibility_factors'].append("Trust structure - may require additional documentation")
            elif 'PARTNERSHIP' in entity_type:
                eligibility_data['eligibility_factors'].append("Partnership structure")
            elif 'SOLE TRADER' in entity_type:
                eligibility_data['warnings'].append("Sole trader - some grants may require incorporated structure")
            
            # Check GST registration
            if business_data['gst_number']:
                eligibility_data['eligibility_factors'].append("GST registered business")
            else:
                eligibility_data['recommendations'].append("Consider GST registration for larger grants")
            
            # Check registration date (not too recent)
            if business_data['registration_date']:
                try:
                    reg_date = datetime.strptime(business_data['registration_date'], '%Y-%m-%d')
                    days_since_registration = (datetime.now() - reg_date).days
                    
                    if days_since_registration < 90:
                        eligibility_data['warnings'].append("Recently registered business - some grants may require minimum operating period")
                    else:
                        eligibility_data['eligibility_factors'].append(f"Established business (registered {days_since_registration} days ago)")
                except:
                    pass
            
            # Check trading names
            if business_data['trading_names']:
                active_names = [tn for tn in business_data['trading_names'] if not tn.get('end_date')]
                if active_names:
                    eligibility_data['eligibility_factors'].append(f"Active trading names: {len(active_names)}")
            
            # Check directors
            if business_data['directors']:
                active_directors = [d for d in business_data['directors'] if not d.get('cessation_date')]
                if active_directors:
                    eligibility_data['eligibility_factors'].append(f"Active directors: {len(active_directors)}")
                else:
                    eligibility_data['warnings'].append("No active directors found")
            
            # Overall eligibility assessment
            if len(eligibility_data['warnings']) == 0:
                eligibility_data['overall_status'] = 'ELIGIBLE'
            elif eligibility_data['is_eligible']:
                eligibility_data['overall_status'] = 'ELIGIBLE_WITH_CONDITIONS'
            else:
                eligibility_data['overall_status'] = 'NOT_ELIGIBLE'
            
            return True, eligibility_data
            
        except Exception as e:
            return False, f"Eligibility verification error: {str(e)}"
    
    def bulk_nzbn_validation(self, nzbn_list):
        """
        Validate multiple NZBNs in batch
        
        Args:
            nzbn_list (list): List of NZBNs to validate
            
        Returns:
            tuple: (success: bool, validation_results: list or error_message: str)
        """
        if len(nzbn_list) > 50:
            return False, "Maximum 50 NZBNs per batch validation"
        
        validation_results = []
        
        for nzbn in nzbn_list:
            try:
                # Validate format
                is_valid, result = self.validate_nzbn(nzbn)
                
                validation_result = {
                    'original_nzbn': nzbn,
                    'is_valid_format': is_valid,
                    'formatted_nzbn': result if is_valid else None,
                    'validation_error': None if is_valid else result
                }
                
                # If format is valid, check NZBN register
                if is_valid:
                    lookup_success, business_data = self.lookup_nzbn_details(nzbn)
                    validation_result['nzbn_lookup_success'] = lookup_success
                    
                    if lookup_success:
                        validation_result['entity_name'] = business_data.get('entity_name', '')
                        validation_result['entity_status'] = business_data.get('entity_status', '')
                        validation_result['entity_type'] = business_data.get('entity_type', '')
                    else:
                        validation_result['nzbn_error'] = business_data
                
                validation_results.append(validation_result)
                
            except Exception as e:
                validation_results.append({
                    'original_nzbn': nzbn,
                    'is_valid_format': False,
                    'validation_error': f"Processing error: {str(e)}"
                })
        
        return True, validation_results
    
    def get_nzbn_status(self):
        """
        Check NZBN API service status
        
        Returns:
            tuple: (success: bool, status_info: dict or error_message: str)
        """
        try:
            # Test authentication
            auth_success, auth_message = self.authenticate()
            
            status_info = {
                'service_name': 'New Zealand Business Number (NZBN)',
                'api_status': 'operational' if auth_success else 'authentication_failed',
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'credentials_configured': bool(self.client_id and self.client_secret),
                'authentication_success': auth_success,
                'response_time_ms': 0
            }
            
            if not auth_success:
                status_info['error_details'] = auth_message
            
            return True, status_info
            
        except Exception as e:
            return False, f"NZBN status check error: {str(e)}"

