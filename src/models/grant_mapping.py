"""
Grant Mapping Models for GrantThrive
Enables public mapping of funded grants and community projects
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class GrantLocation(Base):
    """Model for grant project locations"""
    __tablename__ = 'grant_locations'
    
    id = Column(Integer, primary_key=True)
    grant_id = Column(String(100), nullable=False)  # Links to existing grant system
    application_id = Column(String(100))  # Links to specific application
    
    # Location data
    address = Column(String(500), nullable=False)
    suburb = Column(String(100))
    postcode = Column(String(10))
    state = Column(String(50))
    country = Column(String(50), default="Australia")
    
    # Geographic coordinates
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    
    # Location metadata
    location_type = Column(String(100))  # "Primary", "Secondary", "Service Area"
    is_primary_location = Column(Boolean, default=True)
    is_public_visible = Column(Boolean, default=True)
    
    # Geocoding information
    geocoding_accuracy = Column(String(50))  # "Exact", "Approximate", "Suburb"
    geocoded_at = Column(DateTime)
    geocoding_source = Column(String(100))  # "Google Maps", "Manual Entry"
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    project_updates = relationship("ProjectUpdate", back_populates="location", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<GrantLocation(id={self.id}, grant_id='{self.grant_id}', address='{self.address}')>"

class ProjectUpdate(Base):
    """Model for project progress updates with photos and status"""
    __tablename__ = 'project_updates'
    
    id = Column(Integer, primary_key=True)
    grant_id = Column(String(100), nullable=False)
    location_id = Column(Integer, ForeignKey('grant_locations.id'))
    
    # Update content
    title = Column(String(200), nullable=False)
    description = Column(Text)
    update_type = Column(String(50))  # "Progress", "Milestone", "Completion", "Issue"
    
    # Project status
    completion_percentage = Column(Float, default=0.0)
    project_status = Column(String(50))  # "Planning", "In Progress", "Completed", "On Hold"
    
    # Media attachments
    photos = Column(Text)  # JSON array of photo URLs
    documents = Column(Text)  # JSON array of document URLs
    videos = Column(Text)  # JSON array of video URLs
    
    # Impact metrics
    beneficiaries_count = Column(Integer)
    funds_spent = Column(Float)
    funds_remaining = Column(Float)
    
    # Community engagement
    community_feedback = Column(Text)
    volunteer_hours = Column(Float)
    partnerships_formed = Column(Integer)
    
    # Visibility settings
    is_public = Column(Boolean, default=True)
    is_featured = Column(Boolean, default=False)
    featured_until = Column(DateTime)
    
    # Metadata
    submitted_by = Column(String(100), nullable=False)
    submitted_at = Column(DateTime, default=datetime.utcnow)
    approved_by = Column(String(100))
    approved_at = Column(DateTime)
    
    # Relationships
    location = relationship("GrantLocation", back_populates="project_updates")
    
    def __repr__(self):
        return f"<ProjectUpdate(id={self.id}, grant_id='{self.grant_id}', title='{self.title}')>"

class MapConfiguration(Base):
    """Model for council-specific map configuration"""
    __tablename__ = 'map_configurations'
    
    id = Column(Integer, primary_key=True)
    council_id = Column(String(100), nullable=False, unique=True)
    
    # Map display settings
    default_center_lat = Column(Float, nullable=False)
    default_center_lng = Column(Float, nullable=False)
    default_zoom_level = Column(Integer, default=12)
    
    # Map styling
    map_style = Column(String(50), default="standard")  # "standard", "satellite", "terrain"
    marker_style = Column(String(50), default="default")
    color_scheme = Column(String(100))  # JSON string for custom colors
    
    # Display options
    show_grant_amounts = Column(Boolean, default=True)
    show_project_status = Column(Boolean, default=True)
    show_completion_dates = Column(Boolean, default=True)
    show_beneficiary_count = Column(Boolean, default=False)
    
    # Filtering options
    available_filters = Column(Text)  # JSON array of available filter options
    default_filters = Column(Text)  # JSON array of default active filters
    
    # Public access settings
    is_public_map_enabled = Column(Boolean, default=True)
    require_postcode_verification = Column(Boolean, default=False)
    allow_anonymous_viewing = Column(Boolean, default=True)
    
    # Branding
    council_logo_url = Column(String(500))
    map_title = Column(String(200))
    map_description = Column(Text)
    contact_information = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    updated_by = Column(String(100))
    
    def __repr__(self):
        return f"<MapConfiguration(id={self.id}, council_id='{self.council_id}')>"

class MapAnalytics(Base):
    """Model for tracking map usage and engagement"""
    __tablename__ = 'map_analytics'
    
    id = Column(Integer, primary_key=True)
    council_id = Column(String(100), nullable=False)
    
    # Usage metrics
    total_views = Column(Integer, default=0)
    unique_visitors = Column(Integer, default=0)
    average_session_duration = Column(Float, default=0.0)
    
    # Interaction metrics
    marker_clicks = Column(Integer, default=0)
    filter_usage = Column(Text)  # JSON string of filter usage statistics
    most_viewed_projects = Column(Text)  # JSON array of popular project IDs
    
    # Geographic analysis
    visitor_postcodes = Column(Text)  # JSON string of visitor location data
    popular_map_areas = Column(Text)  # JSON string of frequently viewed areas
    
    # Temporal analysis
    peak_usage_times = Column(Text)  # JSON string of usage patterns
    seasonal_trends = Column(Text)  # JSON string of seasonal usage data
    
    # Engagement metrics
    social_shares = Column(Integer, default=0)
    feedback_submissions = Column(Integer, default=0)
    contact_form_submissions = Column(Integer, default=0)
    
    # Metadata
    analytics_date = Column(DateTime, default=datetime.utcnow)
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<MapAnalytics(id={self.id}, council_id='{self.council_id}', total_views={self.total_views})>"

class CommunityFeedback(Base):
    """Model for community feedback on grant projects"""
    __tablename__ = 'community_feedback'
    
    id = Column(Integer, primary_key=True)
    grant_id = Column(String(100), nullable=False)
    location_id = Column(Integer, ForeignKey('grant_locations.id'))
    
    # Feedback content
    feedback_type = Column(String(50))  # "Positive", "Suggestion", "Concern", "Question"
    feedback_text = Column(Text, nullable=False)
    rating = Column(Integer)  # 1-5 star rating
    
    # Submitter information (anonymized)
    submitter_hash = Column(String(64), nullable=False)
    submitter_postcode = Column(String(10))
    submitter_age_group = Column(String(20))
    
    # Feedback metadata
    is_public = Column(Boolean, default=False)
    is_approved = Column(Boolean, default=False)
    is_flagged = Column(Boolean, default=False)
    flag_reason = Column(String(200))
    
    # Response tracking
    has_response = Column(Boolean, default=False)
    response_text = Column(Text)
    response_by = Column(String(100))
    response_at = Column(DateTime)
    
    # Timestamps
    submitted_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime)
    approved_by = Column(String(100))
    
    # Relationships
    location = relationship("GrantLocation")
    
    def __repr__(self):
        return f"<CommunityFeedback(id={self.id}, grant_id='{self.grant_id}', type='{self.feedback_type}')>"

