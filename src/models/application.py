from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import enum

db = SQLAlchemy()

class ApplicationStatus(enum.Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    REQUIRES_CLARIFICATION = "requires_clarification"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"

class Application(db.Model):
    __tablename__ = 'applications'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Grant and user relationships
    grant_id = db.Column(db.Integer, db.ForeignKey('grants.id'), nullable=False)
    applicant_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Application details
    organization_name = db.Column(db.String(200), nullable=False)
    organization_type = db.Column(db.String(100), nullable=True)
    abn_acn = db.Column(db.String(20), nullable=True)
    
    # Contact information
    contact_person = db.Column(db.String(100), nullable=False)
    contact_email = db.Column(db.String(120), nullable=False)
    contact_phone = db.Column(db.String(20), nullable=True)
    
    # Address
    address_line1 = db.Column(db.String(200), nullable=True)
    address_line2 = db.Column(db.String(200), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(50), nullable=True)
    postcode = db.Column(db.String(10), nullable=True)
    country = db.Column(db.String(50), nullable=True, default='Australia')
    
    # Project details
    project_title = db.Column(db.String(200), nullable=False)
    project_description = db.Column(db.Text, nullable=False)
    project_objectives = db.Column(db.Text, nullable=True)
    project_timeline = db.Column(db.Text, nullable=True)
    
    # Financial information
    requested_amount = db.Column(db.Float, nullable=False)
    total_project_cost = db.Column(db.Float, nullable=True)
    other_funding_sources = db.Column(db.Text, nullable=True)
    budget_breakdown = db.Column(db.Text, nullable=True)  # JSON string
    
    # Impact and outcomes
    expected_outcomes = db.Column(db.Text, nullable=True)
    target_beneficiaries = db.Column(db.Text, nullable=True)
    community_impact = db.Column(db.Text, nullable=True)
    
    # Status and dates
    status = db.Column(db.Enum(ApplicationStatus), nullable=False, default=ApplicationStatus.DRAFT)
    submitted_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Review information
    reviewed_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    review_notes = db.Column(db.Text, nullable=True)
    
    # Additional fields
    supporting_documents = db.Column(db.Text, nullable=True)  # JSON string of file paths
    declaration_accepted = db.Column(db.Boolean, nullable=False, default=False)
    
    # Relationships
    applicant = db.relationship('User', foreign_keys=[applicant_id], backref='applications', lazy=True)
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref='reviewed_applications', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'grant_id': self.grant_id,
            'applicant_id': self.applicant_id,
            'organization_name': self.organization_name,
            'organization_type': self.organization_type,
            'abn_acn': self.abn_acn,
            'contact_person': self.contact_person,
            'contact_email': self.contact_email,
            'contact_phone': self.contact_phone,
            'address_line1': self.address_line1,
            'address_line2': self.address_line2,
            'city': self.city,
            'state': self.state,
            'postcode': self.postcode,
            'country': self.country,
            'project_title': self.project_title,
            'project_description': self.project_description,
            'project_objectives': self.project_objectives,
            'project_timeline': self.project_timeline,
            'requested_amount': self.requested_amount,
            'total_project_cost': self.total_project_cost,
            'other_funding_sources': self.other_funding_sources,
            'budget_breakdown': self.budget_breakdown,
            'expected_outcomes': self.expected_outcomes,
            'target_beneficiaries': self.target_beneficiaries,
            'community_impact': self.community_impact,
            'status': self.status.value if self.status else None,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'reviewed_by': self.reviewed_by,
            'reviewed_at': self.reviewed_at.isoformat() if self.reviewed_at else None,
            'review_notes': self.review_notes,
            'supporting_documents': self.supporting_documents,
            'declaration_accepted': self.declaration_accepted
        }
    
    def __repr__(self):
        return f'<Application {self.project_title} for Grant {self.grant_id}>'

