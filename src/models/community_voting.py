"""
Community Voting Models for GrantThrive
Enables public voting on grant priorities and community engagement
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()

class VotingCampaign(Base):
    """Model for community voting campaigns"""
    __tablename__ = 'voting_campaigns'
    
    id = Column(Integer, primary_key=True)
    council_id = Column(String(100), nullable=False)
    title = Column(String(200), nullable=False)
    description = Column(Text)
    
    # Campaign timing
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)
    
    # Campaign settings
    is_active = Column(Boolean, default=True)
    allow_anonymous_voting = Column(Boolean, default=False)
    max_votes_per_user = Column(Integer, default=3)
    require_address_verification = Column(Boolean, default=True)
    
    # Campaign metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100), nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    voting_options = relationship("VotingOption", back_populates="campaign", cascade="all, delete-orphan")
    votes = relationship("CommunityVote", back_populates="campaign", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<VotingCampaign(id={self.id}, title='{self.title}', council='{self.council_id}')>"

class VotingOption(Base):
    """Model for voting options within a campaign"""
    __tablename__ = 'voting_options'
    
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('voting_campaigns.id'), nullable=False)
    
    # Option details
    title = Column(String(200), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # e.g., "Community Development", "Arts & Culture"
    estimated_budget = Column(Float)
    priority_level = Column(String(50))  # "High", "Medium", "Low"
    
    # Option metadata
    image_url = Column(String(500))
    external_link = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    campaign = relationship("VotingCampaign", back_populates="voting_options")
    votes = relationship("CommunityVote", back_populates="option", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<VotingOption(id={self.id}, title='{self.title}', campaign_id={self.campaign_id})>"

class CommunityVote(Base):
    """Model for individual community votes"""
    __tablename__ = 'community_votes'
    
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('voting_campaigns.id'), nullable=False)
    option_id = Column(Integer, ForeignKey('voting_options.id'), nullable=False)
    
    # Voter information (anonymized for privacy)
    voter_hash = Column(String(64), nullable=False)  # Hashed identifier for duplicate prevention
    voter_postcode = Column(String(10))  # For geographic analysis
    voter_age_group = Column(String(20))  # Optional demographic data
    
    # Vote metadata
    vote_weight = Column(Float, default=1.0)  # Allow weighted voting if needed
    vote_timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address_hash = Column(String(64))  # Hashed IP for fraud prevention
    
    # Verification status
    is_verified = Column(Boolean, default=False)
    verification_method = Column(String(50))  # "email", "sms", "address"
    
    # Relationships
    campaign = relationship("VotingCampaign", back_populates="votes")
    option = relationship("VotingOption", back_populates="votes")
    
    def __repr__(self):
        return f"<CommunityVote(id={self.id}, campaign_id={self.campaign_id}, option_id={self.option_id})>"

class VotingAnalytics(Base):
    """Model for storing voting analytics and insights"""
    __tablename__ = 'voting_analytics'
    
    id = Column(Integer, primary_key=True)
    campaign_id = Column(Integer, ForeignKey('voting_campaigns.id'), nullable=False)
    
    # Analytics data
    total_votes = Column(Integer, default=0)
    unique_voters = Column(Integer, default=0)
    participation_rate = Column(Float, default=0.0)
    
    # Geographic breakdown
    postcode_distribution = Column(Text)  # JSON string of postcode vote counts
    age_group_distribution = Column(Text)  # JSON string of age group breakdown
    
    # Temporal analysis
    voting_pattern = Column(Text)  # JSON string of votes over time
    peak_voting_times = Column(Text)  # JSON string of peak activity periods
    
    # Results summary
    winning_option_id = Column(Integer, ForeignKey('voting_options.id'))
    results_summary = Column(Text)  # JSON string of complete results
    
    # Metadata
    last_updated = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<VotingAnalytics(id={self.id}, campaign_id={self.campaign_id}, total_votes={self.total_votes})>"

class VotingComment(Base):
    """Model for community comments on voting options"""
    __tablename__ = 'voting_comments'
    
    id = Column(Integer, primary_key=True)
    option_id = Column(Integer, ForeignKey('voting_options.id'), nullable=False)
    
    # Comment content
    comment_text = Column(Text, nullable=False)
    commenter_name = Column(String(100))  # Optional display name
    commenter_hash = Column(String(64), nullable=False)  # Anonymized identifier
    
    # Comment metadata
    is_approved = Column(Boolean, default=False)  # Moderation system
    is_flagged = Column(Boolean, default=False)
    flag_reason = Column(String(200))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    approved_at = Column(DateTime)
    approved_by = Column(String(100))
    
    # Relationships
    option = relationship("VotingOption")
    
    def __repr__(self):
        return f"<VotingComment(id={self.id}, option_id={self.option_id}, approved={self.is_approved})>"

