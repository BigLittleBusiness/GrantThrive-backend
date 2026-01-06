"""
Grant Mapping Service for GrantThrive
Handles all grant mapping and location functionality
"""

import json
import requests
from datetime import datetime
from typing import List, Dict, Optional, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_

class GrantMappingService:
    """Service for managing grant locations and public mapping"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.geocoding_api_key = None  # Set from environment variables
    
    def add_grant_location(self, grant_id: str, location_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a location for a grant project"""
        try:
            from ..models.grant_mapping import GrantLocation
            
            # Geocode the address if coordinates not provided
            if not location_data.get('latitude') or not location_data.get('longitude'):
                geocoding_result = self._geocode_address(location_data['address'])
                if geocoding_result['success']:
                    location_data.update(geocoding_result['coordinates'])
                else:
                    return {
                        'success': False,
                        'error': f'Failed to geocode address: {geocoding_result["error"]}'
                    }
            
            location = GrantLocation(
                grant_id=grant_id,
                application_id=location_data.get('application_id'),
                address=location_data['address'],
                suburb=location_data.get('suburb'),
                postcode=location_data.get('postcode'),
                state=location_data.get('state'),
                country=location_data.get('country', 'Australia'),
                latitude=location_data['latitude'],
                longitude=location_data['longitude'],
                location_type=location_data.get('location_type', 'Primary'),
                is_primary_location=location_data.get('is_primary_location', True),
                is_public_visible=location_data.get('is_public_visible', True),
                geocoding_accuracy=location_data.get('geocoding_accuracy', 'Exact'),
                geocoded_at=datetime.utcnow(),
                geocoding_source=location_data.get('geocoding_source', 'Manual Entry')
            )
            
            self.db.add(location)
            self.db.commit()
            self.db.refresh(location)
            
            return {
                'success': True,
                'location_id': location.id,
                'message': 'Grant location added successfully',
                'location': self._serialize_location(location)
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to add grant location: {str(e)}'
            }
    
    def add_project_update(self, grant_id: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a project update with photos and progress information"""
        try:
            from ..models.grant_mapping import ProjectUpdate
            
            update = ProjectUpdate(
                grant_id=grant_id,
                location_id=update_data.get('location_id'),
                title=update_data['title'],
                description=update_data.get('description'),
                update_type=update_data.get('update_type', 'Progress'),
                completion_percentage=update_data.get('completion_percentage', 0.0),
                project_status=update_data.get('project_status', 'In Progress'),
                photos=json.dumps(update_data.get('photos', [])),
                documents=json.dumps(update_data.get('documents', [])),
                videos=json.dumps(update_data.get('videos', [])),
                beneficiaries_count=update_data.get('beneficiaries_count'),
                funds_spent=update_data.get('funds_spent'),
                funds_remaining=update_data.get('funds_remaining'),
                community_feedback=update_data.get('community_feedback'),
                volunteer_hours=update_data.get('volunteer_hours'),
                partnerships_formed=update_data.get('partnerships_formed'),
                is_public=update_data.get('is_public', True),
                is_featured=update_data.get('is_featured', False),
                submitted_by=update_data['submitted_by']
            )
            
            if update_data.get('featured_until'):
                update.featured_until = datetime.fromisoformat(update_data['featured_until'])
            
            self.db.add(update)
            self.db.commit()
            self.db.refresh(update)
            
            return {
                'success': True,
                'update_id': update.id,
                'message': 'Project update added successfully',
                'update': self._serialize_project_update(update)
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to add project update: {str(e)}'
            }
    
    def get_public_grant_map_data(self, council_id: str, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get grant map data for public display"""
        try:
            from ..models.grant_mapping import GrantLocation, ProjectUpdate
            
            # Build base query
            query = self.db.query(GrantLocation).filter(
                GrantLocation.is_public_visible == True
            )
            
            # Apply filters if provided
            if filters:
                if filters.get('postcode'):
                    query = query.filter(GrantLocation.postcode == filters['postcode'])
                
                if filters.get('suburb'):
                    query = query.filter(GrantLocation.suburb.ilike(f"%{filters['suburb']}%"))
                
                if filters.get('project_status'):
                    # Join with project updates to filter by status
                    query = query.join(ProjectUpdate).filter(
                        ProjectUpdate.project_status == filters['project_status']
                    )
            
            locations = query.all()
            
            # Format for map display
            map_data = []
            for location in locations:
                # Get latest project update
                latest_update = self.db.query(ProjectUpdate).filter(
                    and_(
                        ProjectUpdate.grant_id == location.grant_id,
                        ProjectUpdate.is_public == True
                    )
                ).order_by(ProjectUpdate.submitted_at.desc()).first()
                
                location_data = {
                    'id': location.id,
                    'grant_id': location.grant_id,
                    'coordinates': {
                        'lat': location.latitude,
                        'lng': location.longitude
                    },
                    'address': location.address,
                    'suburb': location.suburb,
                    'postcode': location.postcode,
                    'location_type': location.location_type
                }
                
                # Add project information if available
                if latest_update:
                    location_data['project'] = {
                        'title': latest_update.title,
                        'description': latest_update.description,
                        'status': latest_update.project_status,
                        'completion_percentage': latest_update.completion_percentage,
                        'beneficiaries_count': latest_update.beneficiaries_count,
                        'photos': json.loads(latest_update.photos) if latest_update.photos else [],
                        'last_updated': latest_update.submitted_at.isoformat(),
                        'is_featured': latest_update.is_featured
                    }
                
                map_data.append(location_data)
            
            return {
                'success': True,
                'total_locations': len(map_data),
                'locations': map_data
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get map data: {str(e)}'
            }
    
    def get_grant_project_details(self, grant_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific grant project"""
        try:
            from ..models.grant_mapping import GrantLocation, ProjectUpdate, CommunityFeedback
            
            # Get all locations for this grant
            locations = self.db.query(GrantLocation).filter(
                and_(
                    GrantLocation.grant_id == grant_id,
                    GrantLocation.is_public_visible == True
                )
            ).all()
            
            if not locations:
                return {'success': False, 'error': 'Grant project not found or not public'}
            
            # Get all project updates
            updates = self.db.query(ProjectUpdate).filter(
                and_(
                    ProjectUpdate.grant_id == grant_id,
                    ProjectUpdate.is_public == True
                )
            ).order_by(ProjectUpdate.submitted_at.desc()).all()
            
            # Get community feedback
            feedback = self.db.query(CommunityFeedback).filter(
                and_(
                    CommunityFeedback.grant_id == grant_id,
                    CommunityFeedback.is_approved == True
                )
            ).order_by(CommunityFeedback.submitted_at.desc()).all()
            
            # Calculate project statistics
            latest_update = updates[0] if updates else None
            total_funds_spent = sum(update.funds_spent for update in updates if update.funds_spent)
            total_volunteer_hours = sum(update.volunteer_hours for update in updates if update.volunteer_hours)
            total_beneficiaries = max((update.beneficiaries_count for update in updates if update.beneficiaries_count), default=0)
            
            project_details = {
                'grant_id': grant_id,
                'locations': [self._serialize_location(loc) for loc in locations],
                'current_status': latest_update.project_status if latest_update else 'Unknown',
                'completion_percentage': latest_update.completion_percentage if latest_update else 0,
                'statistics': {
                    'total_funds_spent': total_funds_spent,
                    'total_volunteer_hours': total_volunteer_hours,
                    'total_beneficiaries': total_beneficiaries,
                    'total_updates': len(updates),
                    'total_feedback': len(feedback)
                },
                'updates': [self._serialize_project_update(update) for update in updates],
                'community_feedback': [self._serialize_feedback(fb) for fb in feedback]
            }
            
            return {
                'success': True,
                'project': project_details
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Failed to get project details: {str(e)}'
            }
    
    def configure_council_map(self, council_id: str, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Configure map settings for a council"""
        try:
            from ..models.grant_mapping import MapConfiguration
            
            # Get or create configuration
            config = self.db.query(MapConfiguration).filter(
                MapConfiguration.council_id == council_id
            ).first()
            
            if not config:
                config = MapConfiguration(council_id=council_id)
                self.db.add(config)
            
            # Update configuration
            config.default_center_lat = config_data.get('default_center_lat', config.default_center_lat)
            config.default_center_lng = config_data.get('default_center_lng', config.default_center_lng)
            config.default_zoom_level = config_data.get('default_zoom_level', config.default_zoom_level)
            config.map_style = config_data.get('map_style', config.map_style)
            config.marker_style = config_data.get('marker_style', config.marker_style)
            config.show_grant_amounts = config_data.get('show_grant_amounts', config.show_grant_amounts)
            config.show_project_status = config_data.get('show_project_status', config.show_project_status)
            config.show_completion_dates = config_data.get('show_completion_dates', config.show_completion_dates)
            config.is_public_map_enabled = config_data.get('is_public_map_enabled', config.is_public_map_enabled)
            config.council_logo_url = config_data.get('council_logo_url', config.council_logo_url)
            config.map_title = config_data.get('map_title', config.map_title)
            config.map_description = config_data.get('map_description', config.map_description)
            config.updated_by = config_data.get('updated_by', 'system')
            
            if config_data.get('color_scheme'):
                config.color_scheme = json.dumps(config_data['color_scheme'])
            
            if config_data.get('available_filters'):
                config.available_filters = json.dumps(config_data['available_filters'])
            
            if config_data.get('default_filters'):
                config.default_filters = json.dumps(config_data['default_filters'])
            
            self.db.commit()
            
            return {
                'success': True,
                'message': 'Map configuration updated successfully',
                'configuration': self._serialize_map_config(config)
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to configure map: {str(e)}'
            }
    
    def submit_community_feedback(self, grant_id: str, feedback_data: Dict[str, Any]) -> Dict[str, Any]:
        """Submit community feedback for a grant project"""
        try:
            from ..models.grant_mapping import CommunityFeedback
            import hashlib
            
            # Create submitter hash for anonymization
            submitter_identifier = f"{feedback_data.get('email', '')}{feedback_data.get('name', '')}"
            submitter_hash = hashlib.sha256(submitter_identifier.encode()).hexdigest()
            
            feedback = CommunityFeedback(
                grant_id=grant_id,
                location_id=feedback_data.get('location_id'),
                feedback_type=feedback_data.get('feedback_type', 'Positive'),
                feedback_text=feedback_data['feedback_text'],
                rating=feedback_data.get('rating'),
                submitter_hash=submitter_hash,
                submitter_postcode=feedback_data.get('postcode'),
                submitter_age_group=feedback_data.get('age_group'),
                is_public=feedback_data.get('is_public', False)
            )
            
            self.db.add(feedback)
            self.db.commit()
            
            return {
                'success': True,
                'message': 'Feedback submitted for moderation',
                'feedback_id': feedback.id
            }
            
        except Exception as e:
            self.db.rollback()
            return {
                'success': False,
                'error': f'Failed to submit feedback: {str(e)}'
            }
    
    def _geocode_address(self, address: str) -> Dict[str, Any]:
        """Geocode an address using Google Maps API or similar service"""
        try:
            # This is a placeholder implementation
            # In production, you would use Google Maps Geocoding API or similar
            
            # For now, return approximate coordinates for major Australian cities
            city_coordinates = {
                'sydney': {'latitude': -33.8688, 'longitude': 151.2093},
                'melbourne': {'latitude': -37.8136, 'longitude': 144.9631},
                'brisbane': {'latitude': -27.4698, 'longitude': 153.0251},
                'perth': {'latitude': -31.9505, 'longitude': 115.8605},
                'adelaide': {'latitude': -34.9285, 'longitude': 138.6007},
                'canberra': {'latitude': -35.2809, 'longitude': 149.1300}
            }
            
            address_lower = address.lower()
            for city, coords in city_coordinates.items():
                if city in address_lower:
                    return {
                        'success': True,
                        'coordinates': coords,
                        'accuracy': 'Approximate'
                    }
            
            # Default to Sydney coordinates if no match found
            return {
                'success': True,
                'coordinates': {'latitude': -33.8688, 'longitude': 151.2093},
                'accuracy': 'Approximate'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Geocoding failed: {str(e)}'
            }
    
    def _update_map_analytics(self, council_id: str, interaction_type: str, details: Dict[str, Any] = None):
        """Update map usage analytics"""
        try:
            from ..models.grant_mapping import MapAnalytics
            
            # Get or create analytics record for today
            today = datetime.utcnow().date()
            analytics = self.db.query(MapAnalytics).filter(
                and_(
                    MapAnalytics.council_id == council_id,
                    func.date(MapAnalytics.analytics_date) == today
                )
            ).first()
            
            if not analytics:
                analytics = MapAnalytics(
                    council_id=council_id,
                    analytics_date=datetime.utcnow()
                )
                self.db.add(analytics)
            
            # Update metrics based on interaction type
            if interaction_type == 'view':
                analytics.total_views += 1
            elif interaction_type == 'marker_click':
                analytics.marker_clicks += 1
            elif interaction_type == 'social_share':
                analytics.social_shares += 1
            
            self.db.commit()
            
        except Exception as e:
            print(f"Error updating map analytics: {str(e)}")
    
    def _serialize_location(self, location) -> Dict[str, Any]:
        """Serialize location object for API response"""
        return {
            'id': location.id,
            'grant_id': location.grant_id,
            'application_id': location.application_id,
            'address': location.address,
            'suburb': location.suburb,
            'postcode': location.postcode,
            'state': location.state,
            'country': location.country,
            'coordinates': {
                'lat': location.latitude,
                'lng': location.longitude
            },
            'location_type': location.location_type,
            'is_primary_location': location.is_primary_location,
            'geocoding_accuracy': location.geocoding_accuracy,
            'created_at': location.created_at.isoformat()
        }
    
    def _serialize_project_update(self, update) -> Dict[str, Any]:
        """Serialize project update for API response"""
        return {
            'id': update.id,
            'grant_id': update.grant_id,
            'title': update.title,
            'description': update.description,
            'update_type': update.update_type,
            'completion_percentage': update.completion_percentage,
            'project_status': update.project_status,
            'photos': json.loads(update.photos) if update.photos else [],
            'documents': json.loads(update.documents) if update.documents else [],
            'videos': json.loads(update.videos) if update.videos else [],
            'beneficiaries_count': update.beneficiaries_count,
            'funds_spent': update.funds_spent,
            'funds_remaining': update.funds_remaining,
            'community_feedback': update.community_feedback,
            'volunteer_hours': update.volunteer_hours,
            'partnerships_formed': update.partnerships_formed,
            'is_featured': update.is_featured,
            'submitted_at': update.submitted_at.isoformat(),
            'submitted_by': update.submitted_by
        }
    
    def _serialize_feedback(self, feedback) -> Dict[str, Any]:
        """Serialize community feedback for API response"""
        return {
            'id': feedback.id,
            'feedback_type': feedback.feedback_type,
            'feedback_text': feedback.feedback_text,
            'rating': feedback.rating,
            'submitter_postcode': feedback.submitter_postcode,
            'submitted_at': feedback.submitted_at.isoformat(),
            'has_response': feedback.has_response,
            'response_text': feedback.response_text,
            'response_at': feedback.response_at.isoformat() if feedback.response_at else None
        }
    
    def _serialize_map_config(self, config) -> Dict[str, Any]:
        """Serialize map configuration for API response"""
        return {
            'council_id': config.council_id,
            'default_center': {
                'lat': config.default_center_lat,
                'lng': config.default_center_lng
            },
            'default_zoom_level': config.default_zoom_level,
            'map_style': config.map_style,
            'marker_style': config.marker_style,
            'color_scheme': json.loads(config.color_scheme) if config.color_scheme else {},
            'display_options': {
                'show_grant_amounts': config.show_grant_amounts,
                'show_project_status': config.show_project_status,
                'show_completion_dates': config.show_completion_dates
            },
            'available_filters': json.loads(config.available_filters) if config.available_filters else [],
            'default_filters': json.loads(config.default_filters) if config.default_filters else [],
            'is_public_map_enabled': config.is_public_map_enabled,
            'branding': {
                'council_logo_url': config.council_logo_url,
                'map_title': config.map_title,
                'map_description': config.map_description
            }
        }

