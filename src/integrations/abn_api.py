"""
Australian Business Register (ABR) API Integration for GrantThrive Platform
Handles real-time ABN validation and business verification
Official Australian Government business registry integration
"""

import os
import requests
from datetime import datetime
from .base_connector import BaseConnector

class ABRConnector(BaseConnector):
    """
    Australian Business Register API connector for real-time ABN validation
    and business verification using official government data.
    """
    
    def __init__(self):
        super().__init__('ABR')
        self.base_url = "https://abr.business.gov.au/json"
        self.web_services_url = "https://abr.business.gov.au/abrxmlsearch/AbrXmlSearch.asmx"
        # ABR requires a GUID for authentication - obtained from business.gov.au
        self.guid = self._get_credential('GUID')
        
    def authenticate(self):
        """
        ABR API uses GUID-based authentication
        No separate auth step required - GUID is used in each request
        """
        if self.guid and len(self.guid) == 36:  # Standard GUID length
            return True, "ABR GUID configured successfully"
        else:
            return False, "ABR GUID not configured or invalid format"
    
    def validate_abn(self, abn):
        """
        Validate ABN format and checksum using Australian algorithm
        
        Args:
            abn (str): ABN to validate
            
        Returns:
            tuple: (is_valid: bool, formatted_abn: str or error_message: str)
        """
        try:
            # Remove spaces and non-numeric characters
            clean_abn = ''.join(filter(str.isdigit, abn))
            
            # Check length
            if len(clean_abn) != 11:
                return False, "ABN must be 11 digits"
            
            # ABN checksum validation algorithm
            weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
            
            # Subtract 1 from first digit
            digits = [int(d) for d in clean_abn]
            digits[0] -= 1
            
            # Calculate weighted sum
            weighted_sum = sum(digit * weight for digit, weight in zip(digits, weights))
            
            # Check if divisible by 89
            is_valid = weighted_sum % 89 == 0
            
            if is_valid:
                # Format as XX XXX XXX XXX
                formatted = f"{clean_abn[:2]} {clean_abn[2:5]} {clean_abn[5:8]} {clean_abn[8:11]}"
                return True, formatted
            else:
                return False, "Invalid ABN checksum"
                
        except Exception as e:
            return False, f"ABN validation error: {str(e)}"
    
    def lookup_abn_details(self, abn):
        """
        Look up business details from ABR using ABN
        
        Args:
            abn (str): ABN to look up
            
        Returns:
            tuple: (success: bool, business_data: dict or error_message: str)
        """
        if not self.guid:
            return False, "ABR GUID not configured"
        
        # Validate ABN format first
        is_valid, formatted_abn = self.validate_abn(abn)
        if not is_valid:
            return False, formatted_abn
        
        try:
            # Clean ABN for API call
            clean_abn = ''.join(filter(str.isdigit, abn))
            
            # ABR API endpoint for ABN lookup
            url = f"{self.base_url}/AbnDetails.aspx"
            
            params = {
                'abn': clean_abn,
                'guid': self.guid,
                'callback': 'callback'  # JSONP callback
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                # Parse JSONP response
                json_data = response.text
                if json_data.startswith('callback(') and json_data.endswith(')'):
                    json_data = json_data[9:-1]  # Remove callback wrapper
                
                import json
                data = json.loads(json_data)
                
                if 'Abn' in data and data['Abn']:
                    business_data = {
                        'abn': formatted_abn,
                        'abn_status': data['Abn'].get('AbnStatus', ''),
                        'entity_name': data['Abn'].get('EntityName', ''),
                        'entity_type': data['Abn'].get('EntityType', ''),
                        'gst_status': data['Abn'].get('Gst', ''),
                        'dgr_status': data['Abn'].get('DgrEndorsed', False),
                        'acn': data['Abn'].get('Acn', ''),
                        'business_names': [],
                        'addresses': [],
                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    # Extract business names
                    if 'BusinessName' in data['Abn']:
                        business_names = data['Abn']['BusinessName']
                        if isinstance(business_names, list):
                            business_data['business_names'] = [bn.get('OrganisationName', '') for bn in business_names]
                        else:
                            business_data['business_names'] = [business_names.get('OrganisationName', '')]
                    
                    # Extract addresses
                    if 'AddressDetails' in data['Abn']:
                        addresses = data['Abn']['AddressDetails']
                        if isinstance(addresses, list):
                            for addr in addresses:
                                business_data['addresses'].append({
                                    'state': addr.get('State', ''),
                                    'postcode': addr.get('Postcode', ''),
                                    'address_type': addr.get('AddressType', '')
                                })
                        else:
                            business_data['addresses'].append({
                                'state': addresses.get('State', ''),
                                'postcode': addresses.get('Postcode', ''),
                                'address_type': addresses.get('AddressType', '')
                            })
                    
                    return True, business_data
                else:
                    return False, "ABN not found in ABR database"
            else:
                return False, f"ABR API error: {response.status_code}"
                
        except Exception as e:
            return False, f"ABR lookup error: {str(e)}"
    
    def search_business_name(self, business_name):
        """
        Search for businesses by name in ABR
        
        Args:
            business_name (str): Business name to search
            
        Returns:
            tuple: (success: bool, search_results: list or error_message: str)
        """
        if not self.guid:
            return False, "ABR GUID not configured"
        
        try:
            url = f"{self.base_url}/MatchingNames.aspx"
            
            params = {
                'name': business_name,
                'guid': self.guid,
                'maxResults': 20,
                'callback': 'callback'
            }
            
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                # Parse JSONP response
                json_data = response.text
                if json_data.startswith('callback(') and json_data.endswith(')'):
                    json_data = json_data[9:-1]
                
                import json
                data = json.loads(json_data)
                
                search_results = []
                if 'Names' in data and data['Names']:
                    names = data['Names'] if isinstance(data['Names'], list) else [data['Names']]
                    
                    for name_entry in names:
                        result = {
                            'abn': name_entry.get('Abn', ''),
                            'name': name_entry.get('Name', ''),
                            'name_type': name_entry.get('NameType', ''),
                            'state': name_entry.get('State', ''),
                            'postcode': name_entry.get('Postcode', ''),
                            'is_current': name_entry.get('IsCurrent', False)
                        }
                        search_results.append(result)
                
                return True, search_results
            else:
                return False, f"ABR search error: {response.status_code}"
                
        except Exception as e:
            return False, f"ABR search error: {str(e)}"
    
    def verify_grant_eligibility(self, abn):
        """
        Verify if business is eligible for grants based on ABR data
        
        Args:
            abn (str): ABN to verify
            
        Returns:
            tuple: (success: bool, eligibility_data: dict or error_message: str)
        """
        # Get business details first
        success, business_data = self.lookup_abn_details(abn)
        
        if not success:
            return False, business_data
        
        try:
            eligibility_data = {
                'abn': business_data['abn'],
                'entity_name': business_data['entity_name'],
                'is_eligible': True,
                'eligibility_factors': [],
                'warnings': [],
                'recommendations': []
            }
            
            # Check ABN status
            if business_data['abn_status'].upper() != 'ACTIVE':
                eligibility_data['is_eligible'] = False
                eligibility_data['warnings'].append(f"ABN status is {business_data['abn_status']}, not ACTIVE")
            else:
                eligibility_data['eligibility_factors'].append("ABN is active and current")
            
            # Check entity type
            entity_type = business_data['entity_type'].upper()
            if 'COMPANY' in entity_type:
                eligibility_data['eligibility_factors'].append("Registered company structure")
            elif 'TRUST' in entity_type:
                eligibility_data['eligibility_factors'].append("Trust structure - may require additional documentation")
            elif 'PARTNERSHIP' in entity_type:
                eligibility_data['eligibility_factors'].append("Partnership structure")
            elif 'INDIVIDUAL' in entity_type:
                eligibility_data['warnings'].append("Individual trader - some grants may require incorporated structure")
            
            # Check GST registration
            if business_data['gst_status']:
                eligibility_data['eligibility_factors'].append("GST registered business")
            else:
                eligibility_data['recommendations'].append("Consider GST registration for larger grants")
            
            # Check DGR status (Deductible Gift Recipient)
            if business_data['dgr_status']:
                eligibility_data['eligibility_factors'].append("DGR endorsed - eligible for tax-deductible donations")
            
            # Check business names
            if business_data['business_names']:
                eligibility_data['eligibility_factors'].append(f"Registered business names: {', '.join(business_data['business_names'])}")
            
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
    
    def bulk_abn_validation(self, abn_list):
        """
        Validate multiple ABNs in batch
        
        Args:
            abn_list (list): List of ABNs to validate
            
        Returns:
            tuple: (success: bool, validation_results: list or error_message: str)
        """
        if len(abn_list) > 50:
            return False, "Maximum 50 ABNs per batch validation"
        
        validation_results = []
        
        for abn in abn_list:
            try:
                # Validate format
                is_valid, result = self.validate_abn(abn)
                
                validation_result = {
                    'original_abn': abn,
                    'is_valid_format': is_valid,
                    'formatted_abn': result if is_valid else None,
                    'validation_error': None if is_valid else result
                }
                
                # If format is valid, check ABR database
                if is_valid:
                    lookup_success, business_data = self.lookup_abn_details(abn)
                    validation_result['abr_lookup_success'] = lookup_success
                    
                    if lookup_success:
                        validation_result['entity_name'] = business_data.get('entity_name', '')
                        validation_result['abn_status'] = business_data.get('abn_status', '')
                        validation_result['entity_type'] = business_data.get('entity_type', '')
                    else:
                        validation_result['abr_error'] = business_data
                
                validation_results.append(validation_result)
                
            except Exception as e:
                validation_results.append({
                    'original_abn': abn,
                    'is_valid_format': False,
                    'validation_error': f"Processing error: {str(e)}"
                })
        
        return True, validation_results
    
    def get_abr_status(self):
        """
        Check ABR API service status
        
        Returns:
            tuple: (success: bool, status_info: dict or error_message: str)
        """
        try:
            # Test with a known valid ABN (Australian Taxation Office)
            test_abn = "51824753556"
            
            success, result = self.lookup_abn_details(test_abn)
            
            status_info = {
                'service_name': 'Australian Business Register (ABR)',
                'api_status': 'operational' if success else 'degraded',
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'guid_configured': bool(self.guid),
                'test_lookup_success': success,
                'response_time_ms': 0  # Could add timing if needed
            }
            
            if not success:
                status_info['error_details'] = result
            
            return True, status_info
            
        except Exception as e:
            return False, f"ABR status check error: {str(e)}"

