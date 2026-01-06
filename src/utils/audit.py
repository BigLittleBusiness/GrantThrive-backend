import json
from datetime import datetime
from flask import request, g
from src.models.user import db

class AuditLog(db.Model):
    """Audit log model for tracking all system activities"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Event information
    event_type = db.Column(db.String(100), nullable=False)  # CREATE, UPDATE, DELETE, LOGIN, etc.
    resource_type = db.Column(db.String(100), nullable=False)  # USER, GRANT, APPLICATION, etc.
    resource_id = db.Column(db.String(100), nullable=True)  # ID of the affected resource
    
    # User information
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    user_email = db.Column(db.String(120), nullable=True)
    user_role = db.Column(db.String(50), nullable=True)
    
    # Request information
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 compatible
    user_agent = db.Column(db.Text, nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    method = db.Column(db.String(10), nullable=True)
    
    # Event details
    old_values = db.Column(db.Text, nullable=True)  # JSON string of old values
    new_values = db.Column(db.Text, nullable=True)  # JSON string of new values
    additional_data = db.Column(db.Text, nullable=True)  # JSON string of additional context
    
    # Metadata
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text, nullable=True)
    
    # Relationships
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_type': self.event_type,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'user_id': self.user_id,
            'user_email': self.user_email,
            'user_role': self.user_role,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'endpoint': self.endpoint,
            'method': self.method,
            'old_values': json.loads(self.old_values) if self.old_values else None,
            'new_values': json.loads(self.new_values) if self.new_values else None,
            'additional_data': json.loads(self.additional_data) if self.additional_data else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'success': self.success,
            'error_message': self.error_message
        }

class AuditLogger:
    """Audit logging service"""
    
    @staticmethod
    def log_event(event_type, resource_type, resource_id=None, old_values=None, 
                  new_values=None, additional_data=None, success=True, error_message=None):
        """Log an audit event"""
        try:
            # Get current user if available
            user = getattr(g, 'current_user', None)
            
            # Create audit log entry
            audit_log = AuditLog(
                event_type=event_type,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id else None,
                user_id=user.id if user else None,
                user_email=user.email if user else None,
                user_role=user.role if user else None,
                ip_address=request.remote_addr if request else None,
                user_agent=request.headers.get('User-Agent') if request else None,
                endpoint=request.endpoint if request else None,
                method=request.method if request else None,
                old_values=json.dumps(old_values) if old_values else None,
                new_values=json.dumps(new_values) if new_values else None,
                additional_data=json.dumps(additional_data) if additional_data else None,
                success=success,
                error_message=error_message
            )
            
            db.session.add(audit_log)
            db.session.commit()
            
            return audit_log
            
        except Exception as e:
            # Don't let audit logging break the main application
            print(f"Audit logging error: {str(e)}")
            return None
    
    @staticmethod
    def log_authentication(event_type, user_email, success=True, error_message=None):
        """Log authentication events"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='AUTHENTICATION',
            additional_data={'email': user_email},
            success=success,
            error_message=error_message
        )
    
    @staticmethod
    def log_user_action(event_type, user_id, old_values=None, new_values=None):
        """Log user-related actions"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='USER',
            resource_id=user_id,
            old_values=old_values,
            new_values=new_values
        )
    
    @staticmethod
    def log_grant_action(event_type, grant_id, old_values=None, new_values=None):
        """Log grant-related actions"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='GRANT',
            resource_id=grant_id,
            old_values=old_values,
            new_values=new_values
        )
    
    @staticmethod
    def log_application_action(event_type, application_id, old_values=None, new_values=None):
        """Log application-related actions"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='APPLICATION',
            resource_id=application_id,
            old_values=old_values,
            new_values=new_values
        )
    
    @staticmethod
    def log_security_event(event_type, details, severity='INFO'):
        """Log security-related events"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='SECURITY',
            additional_data={
                'details': details,
                'severity': severity
            }
        )
    
    @staticmethod
    def log_data_access(resource_type, resource_id, access_type='READ'):
        """Log data access events"""
        return AuditLogger.log_event(
            event_type=f'DATA_{access_type}',
            resource_type=resource_type,
            resource_id=resource_id
        )
    
    @staticmethod
    def log_system_event(event_type, details):
        """Log system-level events"""
        return AuditLogger.log_event(
            event_type=event_type,
            resource_type='SYSTEM',
            additional_data=details
        )

def audit_decorator(event_type, resource_type):
    """Decorator to automatically audit function calls"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            try:
                # Execute the function
                result = f(*args, **kwargs)
                
                # Log successful execution
                AuditLogger.log_event(
                    event_type=event_type,
                    resource_type=resource_type,
                    additional_data={
                        'function': f.__name__,
                        'args': str(args),
                        'kwargs': str(kwargs)
                    }
                )
                
                return result
                
            except Exception as e:
                # Log failed execution
                AuditLogger.log_event(
                    event_type=event_type,
                    resource_type=resource_type,
                    success=False,
                    error_message=str(e),
                    additional_data={
                        'function': f.__name__,
                        'args': str(args),
                        'kwargs': str(kwargs)
                    }
                )
                raise
        
        return wrapper
    return decorator

class ComplianceReporter:
    """Generate compliance reports from audit logs"""
    
    @staticmethod
    def get_user_activity_report(user_id, start_date=None, end_date=None):
        """Get activity report for a specific user"""
        query = AuditLog.query.filter_by(user_id=user_id)
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        return {
            'user_id': user_id,
            'total_activities': len(logs),
            'activities': [log.to_dict() for log in logs]
        }
    
    @staticmethod
    def get_resource_access_report(resource_type, resource_id, start_date=None, end_date=None):
        """Get access report for a specific resource"""
        query = AuditLog.query.filter_by(resource_type=resource_type, resource_id=str(resource_id))
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        return {
            'resource_type': resource_type,
            'resource_id': resource_id,
            'total_accesses': len(logs),
            'accesses': [log.to_dict() for log in logs]
        }
    
    @staticmethod
    def get_security_events_report(start_date=None, end_date=None, severity=None):
        """Get security events report"""
        query = AuditLog.query.filter_by(resource_type='SECURITY')
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        # Filter by severity if specified
        if severity:
            filtered_logs = []
            for log in logs:
                additional_data = json.loads(log.additional_data) if log.additional_data else {}
                if additional_data.get('severity') == severity:
                    filtered_logs.append(log)
            logs = filtered_logs
        
        return {
            'total_events': len(logs),
            'events': [log.to_dict() for log in logs]
        }
    
    @staticmethod
    def get_failed_operations_report(start_date=None, end_date=None):
        """Get report of failed operations"""
        query = AuditLog.query.filter_by(success=False)
        
        if start_date:
            query = query.filter(AuditLog.timestamp >= start_date)
        
        if end_date:
            query = query.filter(AuditLog.timestamp <= end_date)
        
        logs = query.order_by(AuditLog.timestamp.desc()).all()
        
        return {
            'total_failures': len(logs),
            'failures': [log.to_dict() for log in logs]
        }

