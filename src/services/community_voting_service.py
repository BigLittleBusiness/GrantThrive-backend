"""
Community Voting Service for GrantThrive
Handles all community voting functionality and campaign management
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Any
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

class CommunityVotingService:
    """Service for managing community voting campaigns and votes"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
    
    def create_voting_campaign(self, council_id: str, campaign_data: Dict[str, Any], created_by: str) -> Dict[str, Any]:
        """Create a new community voting campaign"""
        try:
            from ..models.community_voting import VotingCampaign
            
            campaign = VotingCampaign(
                council_id=council_id,
                title=campaign_data['title'],
                description=campaign_data.get('description', ''),
                start_date=datetime.fromisoformat(campaign_data['start_date']),
                end_date=datetime.fromisoformat(campaign_data['end_date']),
                allow_anonymous_voting=campaign_data.get('allow_anonymous_voting', False),
                max_votes_per_user=campaign_data.get('max_votes_per_user', 3),
                require_address_verification=campaign_data.get('require_address_verification', True),
                created_by=created_by
            )
            
            self.db.add(campaign)
            self.db.commit()
            self.db.refresh(campaign)
            
            return {
                'success': True,
                'campaign_id': campaign.id,
                'message': 'Voting campaign created successfully',
                'campaign': self._serialize_campaign(campaign)
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to create voting campaign: {str(e)}'
            }
    
    def add_voting_options(self, campaign_id: int, options: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Add voting options to a campaign"""
        try:
            from ..models.community_voting import VotingOption
            
            created_options = []
            for option_data in options:
                option = VotingOption(
                    campaign_id=campaign_id,
                    title=option_data['title'],
                    description=option_data.get('description', ''),
                    category=option_data.get('category', ''),
                    estimated_budget=option_data.get('estimated_budget'),
                    priority_level=option_data.get('priority_level', 'Medium'),
                    image_url=option_data.get('image_url'),
                    external_link=option_data.get('external_link')
                )
                
                self.db.add(option)
                created_options.append(option)
            
            self.db.commit()
            
            return {
                'success': True,
                'message': f'Added {len(created_options)} voting options',
                'options': [self._serialize_option(opt) for opt in created_options]
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to add voting options: {str(e)}'
            }
    
    def submit_vote(self, campaign_id: int, option_id: int, voter_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit a community vote"""
        try:
            from ..models.community_voting import CommunityVote, VotingCampaign
            
            # Check if campaign is active
            campaign = self.db.query(VotingCampaign).filter(VotingCampaign.id == campaign_id).first()
            if not campaign:
                return {'success': False, 'error': 'Campaign not found'}
            
            now = datetime.utcnow()
            if now < campaign.start_date or now > campaign.end_date:
                return {'success': False, 'error': 'Voting period is not active'}
            
            # Create voter hash for duplicate prevention
            voter_identifier = f"{voter_data.get('email', '')}{voter_data.get('phone', '')}{voter_data.get('address', '')}"
            voter_hash = hashlib.sha256(voter_identifier.encode()).hexdigest()
            
            # Check if user has already voted (if not anonymous)
            if not campaign.allow_anonymous_voting:
                existing_votes = self.db.query(CommunityVote).filter(
                    and_(
                        CommunityVote.campaign_id == campaign_id,
                        CommunityVote.voter_hash == voter_hash
                    )
                ).count()
                
                if existing_votes >= campaign.max_votes_per_user:
                    return {'success': False, 'error': 'Maximum votes per user exceeded'}
            
            # Create IP hash for fraud prevention
            ip_hash = hashlib.sha256(voter_data.get('ip_address', '').encode()).hexdigest()
            
            # Submit vote
            vote = CommunityVote(
                campaign_id=campaign_id,
                option_id=option_id,
                voter_hash=voter_hash,
                voter_postcode=voter_data.get('postcode'),
                voter_age_group=voter_data.get('age_group'),
                ip_address_hash=ip_hash,
                is_verified=voter_data.get('is_verified', False),
                verification_method=voter_data.get('verification_method', 'none')
            )
            
            self.db.add(vote)
            self.db.commit()
            
            # Update analytics
            self._update_voting_analytics(campaign_id)
            
            return {
                'success': True,
                'message': 'Vote submitted successfully',
                'vote_id': vote.id
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to submit vote: {str(e)}'
            }
    
    def get_campaign_results(self, campaign_id: int, include_demographics: bool = False) -> Dict[str, Any]:
        """Get voting results for a campaign"""
        try:
            from ..models.community_voting import VotingCampaign, VotingOption, CommunityVote
            
            campaign = self.db.query(VotingCampaign).filter(VotingCampaign.id == campaign_id).first()
            if not campaign:
                return {'success': False, 'error': 'Campaign not found'}
            
            # Get vote counts by option
            vote_counts = self.db.query(
                VotingOption.id,
                VotingOption.title,
                func.count(CommunityVote.id).label('vote_count')
            ).join(
                CommunityVote, VotingOption.id == CommunityVote.option_id
            ).filter(
                VotingOption.campaign_id == campaign_id
            ).group_by(
                VotingOption.id, VotingOption.title
            ).all()
            
            # Calculate total votes
            total_votes = sum(count.vote_count for count in vote_counts)
            
            # Format results
            results = []
            for count in vote_counts:
                percentage = (count.vote_count / total_votes * 100) if total_votes > 0 else 0
                results.append({
                    'option_id': count.id,
                    'title': count.title,
                    'vote_count': count.vote_count,
                    'percentage': round(percentage, 2)
                })
            
            # Sort by vote count (descending)
            results.sort(key=lambda x: x['vote_count'], reverse=True)
            
            response = {
                'success': True,
                'campaign': self._serialize_campaign(campaign),
                'total_votes': total_votes,
                'results': results
            }
            
            # Add demographic breakdown if requested
            if include_demographics:
                response['demographics'] = self._get_demographic_breakdown(campaign_id)
            
            return response
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get campaign results: {str(e)}'
            }
    
    def get_public_campaigns(self, council_id: str) -> Dict[str, Any]:
        """Get active public voting campaigns for a council"""
        try:
            from ..models.community_voting import VotingCampaign
            
            now = datetime.utcnow()
            campaigns = self.db.query(VotingCampaign).filter(
                and_(
                    VotingCampaign.council_id == council_id,
                    VotingCampaign.is_active == True,
                    VotingCampaign.start_date <= now,
                    VotingCampaign.end_date >= now
                )
            ).all()
            
            return {
                'success': True,
                'campaigns': [self._serialize_campaign_public(campaign) for campaign in campaigns]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get public campaigns: {str(e)}'
            }
    
    def add_comment(self, option_id: int, comment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a comment to a voting option"""
        try:
            from ..models.community_voting import VotingComment
            
            # Create commenter hash for anonymization
            commenter_identifier = f"{comment_data.get('email', '')}{comment_data.get('name', '')}"
            commenter_hash = hashlib.sha256(commenter_identifier.encode()).hexdigest()
            
            comment = VotingComment(
                option_id=option_id,
                comment_text=comment_data['comment_text'],
                commenter_name=comment_data.get('commenter_name'),
                commenter_hash=commenter_hash
            )
            
            self.db.add(comment)
            self.db.commit()
            
            return {
                'success': True,
                'message': 'Comment submitted for moderation',
                'comment_id': comment.id
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to add comment: {str(e)}'
            }
    
    def _update_voting_analytics(self, campaign_id: int):
        """Update voting analytics for a campaign"""
        try:
            from ..models.community_voting import VotingAnalytics, CommunityVote
            
            # Get or create analytics record
            analytics = self.db.query(VotingAnalytics).filter(
                VotingAnalytics.campaign_id == campaign_id
            ).first()
            
            if not analytics:
                from ..models.community_voting import VotingAnalytics
                analytics = VotingAnalytics(campaign_id=campaign_id)
                self.db.add(analytics)
            
            # Calculate metrics
            votes = self.db.query(CommunityVote).filter(
                CommunityVote.campaign_id == campaign_id
            ).all()
            
            analytics.total_votes = len(votes)
            analytics.unique_voters = len(set(vote.voter_hash for vote in votes))
            
            # Update postcode distribution
            postcode_counts = {}
            for vote in votes:
                if vote.voter_postcode:
                    postcode_counts[vote.voter_postcode] = postcode_counts.get(vote.voter_postcode, 0) + 1
            analytics.postcode_distribution = json.dumps(postcode_counts)
            
            # Update age group distribution
            age_counts = {}
            for vote in votes:
                if vote.voter_age_group:
                    age_counts[vote.voter_age_group] = age_counts.get(vote.voter_age_group, 0) + 1
            analytics.age_group_distribution = json.dumps(age_counts)
            
            self.db.commit()
            
        except Exception as e:
            print(f"Error updating voting analytics: {str(e)}")
    
    def _get_demographic_breakdown(self, campaign_id: int) -> Dict[str, Any]:
        """Get demographic breakdown for campaign results"""
        from ..models.community_voting import CommunityVote
        
        votes = self.db.query(CommunityVote).filter(
            CommunityVote.campaign_id == campaign_id
        ).all()
        
        # Postcode breakdown
        postcode_counts = {}
        for vote in votes:
            if vote.voter_postcode:
                postcode_counts[vote.voter_postcode] = postcode_counts.get(vote.voter_postcode, 0) + 1
        
        # Age group breakdown
        age_counts = {}
        for vote in votes:
            if vote.voter_age_group:
                age_counts[vote.voter_age_group] = age_counts.get(vote.voter_age_group, 0) + 1
        
        return {
            'postcode_distribution': postcode_counts,
            'age_group_distribution': age_counts
        }
    
    def _serialize_campaign(self, campaign) -> Dict[str, Any]:
        """Serialize campaign object for API response"""
        return {
            'id': campaign.id,
            'council_id': campaign.council_id,
            'title': campaign.title,
            'description': campaign.description,
            'start_date': campaign.start_date.isoformat(),
            'end_date': campaign.end_date.isoformat(),
            'is_active': campaign.is_active,
            'allow_anonymous_voting': campaign.allow_anonymous_voting,
            'max_votes_per_user': campaign.max_votes_per_user,
            'require_address_verification': campaign.require_address_verification,
            'created_at': campaign.created_at.isoformat(),
            'created_by': campaign.created_by
        }
    
    def _serialize_campaign_public(self, campaign) -> Dict[str, Any]:
        """Serialize campaign for public API (limited information)"""
        return {
            'id': campaign.id,
            'title': campaign.title,
            'description': campaign.description,
            'start_date': campaign.start_date.isoformat(),
            'end_date': campaign.end_date.isoformat(),
            'max_votes_per_user': campaign.max_votes_per_user,
            'options': [self._serialize_option(opt) for opt in campaign.voting_options]
        }
    
    def _serialize_option(self, option) -> Dict[str, Any]:
        """Serialize voting option for API response"""
        return {
            'id': option.id,
            'title': option.title,
            'description': option.description,
            'category': option.category,
            'estimated_budget': option.estimated_budget,
            'priority_level': option.priority_level,
            'image_url': option.image_url,
            'external_link': option.external_link
        }

