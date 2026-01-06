import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class EncryptionManager:
    """Handles encryption and decryption of sensitive data"""
    
    def __init__(self, password=None):
        """Initialize encryption manager with password or environment variable"""
        if password is None:
            password = os.environ.get('GRANTTHRIVE_ENCRYPTION_KEY', 'default-key-change-in-production')
        
        self.password = password.encode()
        self.salt = b'grantthrive_salt'  # In production, use random salt per encryption
        
    def _get_key(self):
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt(self, data):
        """Encrypt sensitive data"""
        if not data:
            return None
        
        if isinstance(data, str):
            data = data.encode()
        
        f = Fernet(self._get_key())
        encrypted_data = f.encrypt(data)
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt sensitive data"""
        if not encrypted_data:
            return None
        
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
            f = Fernet(self._get_key())
            decrypted_data = f.decrypt(encrypted_bytes)
            return decrypted_data.decode()
        except Exception:
            return None
    
    def hash_data(self, data):
        """Create one-way hash of data"""
        if isinstance(data, str):
            data = data.encode()
        
        return hashlib.sha256(data).hexdigest()
    
    def verify_hash(self, data, hash_value):
        """Verify data against hash"""
        return self.hash_data(data) == hash_value

# Global encryption manager instance
encryption_manager = EncryptionManager()

def encrypt_sensitive_field(data):
    """Encrypt a sensitive field"""
    return encryption_manager.encrypt(data)

def decrypt_sensitive_field(encrypted_data):
    """Decrypt a sensitive field"""
    return encryption_manager.decrypt(encrypted_data)

def hash_sensitive_data(data):
    """Hash sensitive data for storage"""
    return encryption_manager.hash_data(data)

def verify_sensitive_data(data, hash_value):
    """Verify sensitive data against hash"""
    return encryption_manager.verify_hash(data, hash_value)

class SecureDataHandler:
    """Handles secure storage and retrieval of sensitive application data"""
    
    @staticmethod
    def encrypt_document_metadata(metadata):
        """Encrypt document metadata"""
        if not metadata:
            return None
        
        sensitive_fields = ['file_path', 'original_filename']
        encrypted_metadata = metadata.copy()
        
        for field in sensitive_fields:
            if field in encrypted_metadata:
                encrypted_metadata[field] = encrypt_sensitive_field(encrypted_metadata[field])
        
        return encrypted_metadata
    
    @staticmethod
    def decrypt_document_metadata(encrypted_metadata):
        """Decrypt document metadata"""
        if not encrypted_metadata:
            return None
        
        sensitive_fields = ['file_path', 'original_filename']
        decrypted_metadata = encrypted_metadata.copy()
        
        for field in sensitive_fields:
            if field in decrypted_metadata:
                decrypted_metadata[field] = decrypt_sensitive_field(decrypted_metadata[field])
        
        return decrypted_metadata
    
    @staticmethod
    def encrypt_financial_data(financial_data):
        """Encrypt financial information"""
        if not financial_data:
            return None
        
        sensitive_fields = ['bank_account', 'bsb', 'account_number', 'abn']
        encrypted_data = financial_data.copy()
        
        for field in sensitive_fields:
            if field in encrypted_data:
                encrypted_data[field] = encrypt_sensitive_field(encrypted_data[field])
        
        return encrypted_data
    
    @staticmethod
    def decrypt_financial_data(encrypted_data):
        """Decrypt financial information"""
        if not encrypted_data:
            return None
        
        sensitive_fields = ['bank_account', 'bsb', 'account_number', 'abn']
        decrypted_data = encrypted_data.copy()
        
        for field in sensitive_fields:
            if field in decrypted_data:
                decrypted_data[field] = decrypt_sensitive_field(decrypted_data[field])
        
        return decrypted_data
    
    @staticmethod
    def anonymize_personal_data(data):
        """Anonymize personal data for analytics"""
        if not data:
            return None
        
        anonymized = data.copy()
        
        # Hash personally identifiable information
        pii_fields = ['email', 'phone', 'abn_acn']
        for field in pii_fields:
            if field in anonymized and anonymized[field]:
                anonymized[field] = hash_sensitive_data(anonymized[field])
        
        # Remove or mask other sensitive fields
        sensitive_fields = ['first_name', 'last_name', 'address']
        for field in sensitive_fields:
            if field in anonymized:
                anonymized[field] = '***'
        
        return anonymized

def generate_secure_token(length=32):
    """Generate a secure random token"""
    return base64.urlsafe_b64encode(os.urandom(length)).decode()

def secure_compare(a, b):
    """Secure string comparison to prevent timing attacks"""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    
    return result == 0

