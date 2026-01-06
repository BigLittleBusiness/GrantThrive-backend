"""
Base Connector Class for GrantThrive Platform Integrations
Provides common functionality for all API integrations
"""

import os
import requests
from datetime import datetime
from typing import Dict, Optional
from abc import ABC, abstractmethod

class BaseConnector(ABC):
    """
    Abstract base class for all API connectors
    """
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.last_sync = None
        self.connection_status = 'disconnected'
        
    @abstractmethod
    def test_connection(self) -> Dict:
        """
        Test connection to the external service
        
        Returns:
            dict: Connection test result
        """
        pass
    
    @abstractmethod
    def get_integration_status(self) -> Dict:
        """
        Get current integration status
        
        Returns:
            dict: Integration status information
        """
        pass
    
    def log_sync_attempt(self, operation: str, success: bool, details: str = None):
        """
        Log synchronization attempt
        
        Args:
            operation (str): Operation performed
            success (bool): Whether operation was successful
            details (str, optional): Additional details
        """
        self.last_sync = datetime.now().isoformat()
        
        # In production, this would log to a database or logging service
        log_entry = {
            'service': self.service_name,
            'operation': operation,
            'success': success,
            'timestamp': self.last_sync,
            'details': details
        }
        
        print(f"[{self.service_name}] {operation}: {'SUCCESS' if success else 'FAILED'}")
        if details:
            print(f"[{self.service_name}] Details: {details}")
    
    def format_error_response(self, error_message: str, operation: str = None) -> Dict:
        """
        Format standardized error response
        
        Args:
            error_message (str): Error message
            operation (str, optional): Operation that failed
            
        Returns:
            dict: Formatted error response
        """
        return {
            'success': False,
            'service': self.service_name,
            'operation': operation,
            'error': error_message,
            'timestamp': datetime.now().isoformat()
        }
    
    def format_success_response(self, data: Dict, operation: str = None) -> Dict:
        """
        Format standardized success response
        
        Args:
            data (dict): Response data
            operation (str, optional): Operation that succeeded
            
        Returns:
            dict: Formatted success response
        """
        response = {
            'success': True,
            'service': self.service_name,
            'operation': operation,
            'timestamp': datetime.now().isoformat()
        }
        response.update(data)
        return response
    
    def make_api_request(self, method: str, url: str, headers: Dict = None, 
                        data: Dict = None, timeout: int = 30) -> requests.Response:
        """
        Make API request with common error handling
        
        Args:
            method (str): HTTP method
            url (str): Request URL
            headers (dict, optional): Request headers
            data (dict, optional): Request data
            timeout (int): Request timeout in seconds
            
        Returns:
            requests.Response: API response
            
        Raises:
            requests.exceptions.RequestException: On request failure
        """
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                timeout=timeout
            )
            
            # Log the request
            self.log_sync_attempt(
                f"{method} {url}",
                response.status_code < 400,
                f"Status: {response.status_code}"
            )
            
            return response
            
        except requests.exceptions.RequestException as e:
            self.log_sync_attempt(f"{method} {url}", False, str(e))
            raise
    
    def validate_required_fields(self, data: Dict, required_fields: list) -> Dict:
        """
        Validate that required fields are present in data
        
        Args:
            data (dict): Data to validate
            required_fields (list): List of required field names
            
        Returns:
            dict: Validation result
        """
        missing_fields = []
        
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == '':
                missing_fields.append(field)
        
        if missing_fields:
            return {
                'valid': False,
                'missing_fields': missing_fields,
                'error': f"Missing required fields: {', '.join(missing_fields)}"
            }
        
        return {'valid': True}
    
    def sanitize_data(self, data: Dict) -> Dict:
        """
        Sanitize data by removing None values and empty strings
        
        Args:
            data (dict): Data to sanitize
            
        Returns:
            dict: Sanitized data
        """
        return {k: v for k, v in data.items() if v is not None and v != ''}
    
    def get_config_value(self, key: str, default: str = None) -> str:
        """
        Get configuration value from environment variables
        
        Args:
            key (str): Configuration key
            default (str, optional): Default value if key not found
            
        Returns:
            str: Configuration value
        """
        return os.getenv(key, default)
    
    def is_connected(self) -> bool:
        """
        Check if connector is currently connected
        
        Returns:
            bool: Connection status
        """
        return self.connection_status == 'connected'
    
    def set_connection_status(self, status: str):
        """
        Set connection status
        
        Args:
            status (str): Connection status ('connected', 'disconnected', 'error')
        """
        self.connection_status = status

