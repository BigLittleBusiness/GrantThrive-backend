from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum

db = SQLAlchemy()

class GrantStatus(enum.Enum):
    DRAFT = "draft"
    OPEN = "open"
    CLOSING_SOON = "closing_soon"
    CLOSED = "closed"
    UNDER_REVIEW = "under_review"
    COMPLETED = "completed"

class GrantCategory(enum.Enum):
    COMMUNITY_DEVELOPMENT = "community_development"
    ARTS_CULTURE = "arts_culture"
    ENVIRONMENT = "environment"
    EDUCATION = "education"
    HEALTH_WELLBEING = "health_wellbeing"
    INFRASTRUCTURE = "infrastructure"
    ECONOMIC_DEVELOPMENT = "economic_development"
    YOUTH_PROGRAMS = "youth_programs"
    SENIORS_PROGRAMS = "seniors_programs"
    DISABILITY_SUPPORT = "disability_support"

class Grant(db.Model):
    __tablename__ = 'grants'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    short_description = db.Column(db.String(500), nullable=True)
    
    # Financial details
    funding_amount = db.Column(db.Float, nullable=False)
    min_funding = db.Column(db.Float, nullable=True)
    max_funding = db.Column(db.Float, nullable=True)
    
    # Dates
    open_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    close_date = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Status and categorization
    status = db.Column(db.Enum(GrantStatus), nullable=False, default=GrantStatus.DRAFT)
    category = db.Column(db.Enum(GrantCategory), nullable=False)
    
    # Eligibility and requirements
    eligibility_criteria = db.Column(db.Text, nullable=True)
    required_documents = db.Column(db.Text, nullable=True)  # JSON string of document types
    
    # Organization details
    organization_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    contact_email = db.Column(db.String(120), nullable=False)
    contact_phone = db.Column(db.String(20), nullable=True)
    
    # Additional fields
    tags = db.Column(db.Text, nullable=True)  # JSON string of tags
    location_restrictions = db.Column(db.String(200), nullable=True)
    website_url = db.Column(db.String(200), nullable=True)
    
    # Statistics
    view_count = db.Column(db.Integer, default=0)
    application_count = db.Column(db.Integer, default=0)
    
    # Relationships
    applications = db.relationship('Application', backref='grant', lazy=True, cascade='all, delete-orphan')
    created_by = db.relationship('User', backref='created_grants', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'short_description': self.short_description,
            'funding_amount': self.funding_amount,
            'min_funding': self.min_funding,
            'max_funding': self.max_funding,
            'open_date': self.open_date.isoformat() if self.open_date else None,
            'close_date': self.close_date.isoformat() if self.close_date else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'status': self.status.value if self.status else None,
            'category': self.category.value if self.category else None,
            'eligibility_criteria': self.eligibility_criteria,
            'required_documents': self.required_documents,
            'organization_id': self.organization_id,
            'contact_email': self.contact_email,
            'contact_phone': self.contact_phone,
            'tags': self.tags,
            'location_restrictions': self.location_restrictions,
            'website_url': self.website_url,
            'view_count': self.view_count,
            'application_count': self.application_count
        }
    
    def __repr__(self):
        return f'<Grant {self.title}>'

