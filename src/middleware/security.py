import re
import time
from functools import wraps
from flask import request, jsonify, g
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Rate limiting storage (in production, use Redis)
rate_limit_storage = defaultdict(lambda: deque())

def validate_input(f):
    """Decorator to validate and sanitize input data"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.is_json:
            data = request.get_json()
            if data:
                # Sanitize string inputs
                sanitized_data = sanitize_data(data)
                request._cached_json = sanitized_data
        
        return f(*args, **kwargs)
    
    return decorated_function

def sanitize_data(data):
    """Recursively sanitize data to prevent XSS and injection attacks"""
    if isinstance(data, dict):
        return {key: sanitize_data(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    elif isinstance(data, str):
        # Remove potentially dangerous characters and scripts
        data = re.sub(r'<script[^>]*>.*?</script>', '', data, flags=re.IGNORECASE | re.DOTALL)
        data = re.sub(r'javascript:', '', data, flags=re.IGNORECASE)
        data = re.sub(r'on\w+\s*=', '', data, flags=re.IGNORECASE)
        return data.strip()
    else:
        return data

def rate_limit(max_requests=100, window_minutes=15):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP address or user ID if authenticated)
            client_id = request.remote_addr
            if hasattr(g, 'current_user') and g.current_user:
                client_id = f"user_{g.current_user.id}"
            
            now = datetime.utcnow()
            window_start = now - timedelta(minutes=window_minutes)
            
            # Clean old requests
            client_requests = rate_limit_storage[client_id]
            while client_requests and client_requests[0] < window_start:
                client_requests.popleft()
            
            # Check rate limit
            if len(client_requests) >= max_requests:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after': window_minutes * 60
                }), 429
            
            # Add current request
            client_requests.append(now)
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    """Validate Australian phone number format"""
    if not phone:
        return True  # Phone is optional
    
    # Remove spaces, dashes, and parentheses
    cleaned = re.sub(r'[\s\-\(\)]', '', phone)
    
    # Australian phone number patterns
    patterns = [
        r'^(\+61|0)[2-9]\d{8}$',  # Landline
        r'^(\+61|0)4\d{8}$',      # Mobile
        r'^(\+61|0)1[38]\d{8}$',  # Special services
    ]
    
    return any(re.match(pattern, cleaned) for pattern in patterns)

def validate_abn(abn):
    """Validate Australian Business Number (ABN)"""
    if not abn:
        return True  # ABN is optional
    
    # Remove spaces and dashes
    cleaned = re.sub(r'[\s\-]', '', abn)
    
    # Check if it's 11 digits
    if not re.match(r'^\d{11}$', cleaned):
        return False
    
    # ABN checksum validation
    weights = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
    
    # Subtract 1 from the first digit
    digits = [int(d) for d in cleaned]
    digits[0] -= 1
    
    # Calculate checksum
    checksum = sum(digit * weight for digit, weight in zip(digits, weights))
    
    return checksum % 89 == 0

def validate_password_strength(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character"
    
    return True, "Password is strong"

def validate_grant_data(data):
    """Validate grant creation/update data"""
    errors = []
    
    # Required fields
    required_fields = ['title', 'description', 'category', 'amount']
    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field} is required")
    
    # Validate amount
    if data.get('amount'):
        try:
            amount = float(data['amount'])
            if amount <= 0:
                errors.append("Amount must be greater than 0")
            if amount > 10000000:  # 10 million limit
                errors.append("Amount cannot exceed $10,000,000")
        except (ValueError, TypeError):
            errors.append("Amount must be a valid number")
    
    # Validate dates
    if data.get('opens_at') and data.get('closes_at'):
        try:
            opens_at = datetime.fromisoformat(data['opens_at'].replace('Z', '+00:00'))
            closes_at = datetime.fromisoformat(data['closes_at'].replace('Z', '+00:00'))
            
            if closes_at <= opens_at:
                errors.append("Closing date must be after opening date")
            
            if opens_at < datetime.utcnow():
                errors.append("Opening date cannot be in the past")
                
        except ValueError:
            errors.append("Invalid date format")
    
    # Validate email if provided
    if data.get('contact_email') and not validate_email(data['contact_email']):
        errors.append("Invalid contact email format")
    
    # Validate phone if provided
    if data.get('contact_phone') and not validate_phone(data['contact_phone']):
        errors.append("Invalid contact phone format")
    
    return errors

def validate_application_data(data):
    """Validate application submission data"""
    errors = []
    
    # Required fields
    required_fields = [
        'grant_id', 'applicant_name', 'applicant_email',
        'project_title', 'project_description', 'requested_amount'
    ]
    for field in required_fields:
        if not data.get(field):
            errors.append(f"{field} is required")
    
    # Validate email
    if data.get('applicant_email') and not validate_email(data['applicant_email']):
        errors.append("Invalid applicant email format")
    
    # Validate phone if provided
    if data.get('applicant_phone') and not validate_phone(data['applicant_phone']):
        errors.append("Invalid applicant phone format")
    
    # Validate ABN if provided
    if data.get('abn_acn') and not validate_abn(data['abn_acn']):
        errors.append("Invalid ABN format")
    
    # Validate requested amount
    if data.get('requested_amount'):
        try:
            amount = float(data['requested_amount'])
            if amount <= 0:
                errors.append("Requested amount must be greater than 0")
            if amount > 10000000:  # 10 million limit
                errors.append("Requested amount cannot exceed $10,000,000")
        except (ValueError, TypeError):
            errors.append("Requested amount must be a valid number")
    
    # Validate project dates
    if data.get('project_start_date') and data.get('project_end_date'):
        try:
            start_date = datetime.strptime(data['project_start_date'], '%Y-%m-%d').date()
            end_date = datetime.strptime(data['project_end_date'], '%Y-%m-%d').date()
            
            if end_date <= start_date:
                errors.append("Project end date must be after start date")
                
        except ValueError:
            errors.append("Invalid project date format (use YYYY-MM-DD)")
    
    return errors

def log_security_event(event_type, details, user_id=None, ip_address=None):
    """Log security events for monitoring"""
    timestamp = datetime.utcnow().isoformat()
    
    log_entry = {
        'timestamp': timestamp,
        'event_type': event_type,
        'details': details,
        'user_id': user_id,
        'ip_address': ip_address or request.remote_addr,
        'user_agent': request.headers.get('User-Agent', 'Unknown')
    }
    
    # In production, send to proper logging system
    print(f"SECURITY EVENT: {log_entry}")
    
    return log_entry

