"""
Real-Time Progress Tracking Service for GrantThrive Platform
Provides live progress updates and status tracking for grant applications
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from enum import Enum

class ApplicationStatus(Enum):
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    ADDITIONAL_INFO_REQUIRED = "additional_info_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"

class ProgressStage(Enum):
    APPLICATION_CREATION = "application_creation"
    DOCUMENT_UPLOAD = "document_upload"
    SUBMISSION = "submission"
    INITIAL_REVIEW = "initial_review"
    DETAILED_ASSESSMENT = "detailed_assessment"
    DECISION = "decision"
    NOTIFICATION = "notification"
    FUNDING_SETUP = "funding_setup"
    REPORTING = "reporting"

class ProgressTrackingService:
    """
    Service for tracking and managing application progress in real-time
    """
    
    def __init__(self):
        # In-memory storage for demo (in production, use database)
        self.application_progress = {}
        self.progress_templates = self._initialize_progress_templates()
        self.status_workflows = self._initialize_status_workflows()
        
    def _initialize_progress_templates(self):
        """
        Initialize progress templates for different grant types
        """
        return {
            'standard_grant': {
                'stages': [
                    {
                        'stage': ProgressStage.APPLICATION_CREATION,
                        'title': 'Create Application',
                        'description': 'Complete your grant application form',
                        'estimated_duration': 60,  # minutes
                        'required_fields': ['organization_info', 'project_description', 'budget'],
                        'optional_fields': ['supporting_documents'],
                        'completion_criteria': 'all_required_fields_completed'
                    },
                    {
                        'stage': ProgressStage.DOCUMENT_UPLOAD,
                        'title': 'Upload Documents',
                        'description': 'Upload required supporting documents',
                        'estimated_duration': 30,
                        'required_fields': ['financial_statements', 'project_plan'],
                        'optional_fields': ['letters_of_support', 'additional_evidence'],
                        'completion_criteria': 'all_required_documents_uploaded'
                    },
                    {
                        'stage': ProgressStage.SUBMISSION,
                        'title': 'Submit Application',
                        'description': 'Review and submit your completed application',
                        'estimated_duration': 15,
                        'required_fields': ['final_review', 'declaration'],
                        'optional_fields': [],
                        'completion_criteria': 'application_submitted'
                    },
                    {
                        'stage': ProgressStage.INITIAL_REVIEW,
                        'title': 'Initial Review',
                        'description': 'Council staff review application for completeness',
                        'estimated_duration': 2880,  # 2 days in minutes
                        'council_stage': True,
                        'completion_criteria': 'initial_review_completed'
                    },
                    {
                        'stage': ProgressStage.DETAILED_ASSESSMENT,
                        'title': 'Detailed Assessment',
                        'description': 'Comprehensive evaluation of application merit',
                        'estimated_duration': 10080,  # 7 days in minutes
                        'council_stage': True,
                        'completion_criteria': 'assessment_completed'
                    },
                    {
                        'stage': ProgressStage.DECISION,
                        'title': 'Decision',
                        'description': 'Final decision on grant application',
                        'estimated_duration': 1440,  # 1 day in minutes
                        'council_stage': True,
                        'completion_criteria': 'decision_made'
                    },
                    {
                        'stage': ProgressStage.NOTIFICATION,
                        'title': 'Notification',
                        'description': 'Applicant notified of decision',
                        'estimated_duration': 60,
                        'council_stage': True,
                        'completion_criteria': 'applicant_notified'
                    }
                ]
            },
            'quick_grant': {
                'stages': [
                    {
                        'stage': ProgressStage.APPLICATION_CREATION,
                        'title': 'Quick Application',
                        'description': 'Complete simplified application form',
                        'estimated_duration': 30,
                        'required_fields': ['organization_info', 'project_summary', 'amount_requested'],
                        'completion_criteria': 'all_required_fields_completed'
                    },
                    {
                        'stage': ProgressStage.SUBMISSION,
                        'title': 'Submit Application',
                        'description': 'Submit your quick grant application',
                        'estimated_duration': 5,
                        'required_fields': ['declaration'],
                        'completion_criteria': 'application_submitted'
                    },
                    {
                        'stage': ProgressStage.INITIAL_REVIEW,
                        'title': 'Fast-Track Review',
                        'description': 'Expedited review process',
                        'estimated_duration': 1440,  # 1 day
                        'council_stage': True,
                        'completion_criteria': 'review_completed'
                    },
                    {
                        'stage': ProgressStage.DECISION,
                        'title': 'Decision',
                        'description': 'Quick decision on application',
                        'estimated_duration': 480,  # 8 hours
                        'council_stage': True,
                        'completion_criteria': 'decision_made'
                    },
                    {
                        'stage': ProgressStage.NOTIFICATION,
                        'title': 'Notification',
                        'description': 'Immediate notification of outcome',
                        'estimated_duration': 30,
                        'council_stage': True,
                        'completion_criteria': 'applicant_notified'
                    }
                ]
            }
        }
    
    def _initialize_status_workflows(self):
        """
        Initialize status workflow mappings
        """
        return {
            ApplicationStatus.DRAFT: [ProgressStage.APPLICATION_CREATION, ProgressStage.DOCUMENT_UPLOAD],
            ApplicationStatus.SUBMITTED: [ProgressStage.SUBMISSION],
            ApplicationStatus.UNDER_REVIEW: [ProgressStage.INITIAL_REVIEW, ProgressStage.DETAILED_ASSESSMENT],
            ApplicationStatus.ADDITIONAL_INFO_REQUIRED: [ProgressStage.INITIAL_REVIEW],
            ApplicationStatus.APPROVED: [ProgressStage.DECISION, ProgressStage.NOTIFICATION],
            ApplicationStatus.REJECTED: [ProgressStage.DECISION, ProgressStage.NOTIFICATION],
            ApplicationStatus.WITHDRAWN: []
        }
    
    def initialize_application_progress(self, application_id: str, grant_type: str = 'standard_grant', 
                                      custom_stages: List[Dict] = None) -> Dict:
        """
        Initialize progress tracking for new application
        
        Args:
            application_id (str): Application identifier
            grant_type (str): Type of grant (determines progress template)
            custom_stages (list, optional): Custom progress stages
            
        Returns:
            dict: Initialization result
        """
        try:
            # Get progress template
            if custom_stages:
                stages = custom_stages
            else:
                template = self.progress_templates.get(grant_type, self.progress_templates['standard_grant'])
                stages = template['stages']
            
            # Initialize progress tracking
            progress_data = {
                'application_id': application_id,
                'grant_type': grant_type,
                'current_stage': 0,
                'current_status': ApplicationStatus.DRAFT.value,
                'overall_progress': 0.0,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'estimated_completion': self._calculate_estimated_completion(stages),
                'stages': []
            }
            
            # Initialize each stage
            for i, stage_template in enumerate(stages):
                stage_data = {
                    'stage_index': i,
                    'stage': stage_template['stage'].value,
                    'title': stage_template['title'],
                    'description': stage_template['description'],
                    'status': 'pending',
                    'progress': 0.0,
                    'started_at': None,
                    'completed_at': None,
                    'estimated_duration': stage_template['estimated_duration'],
                    'actual_duration': None,
                    'required_fields': stage_template.get('required_fields', []),
                    'optional_fields': stage_template.get('optional_fields', []),
                    'completed_fields': [],
                    'council_stage': stage_template.get('council_stage', False),
                    'completion_criteria': stage_template['completion_criteria'],
                    'notes': [],
                    'blockers': []
                }
                
                # Start first stage immediately
                if i == 0:
                    stage_data['status'] = 'in_progress'
                    stage_data['started_at'] = datetime.now().isoformat()
                
                progress_data['stages'].append(stage_data)
            
            # Store progress data
            self.application_progress[application_id] = progress_data
            
            return {
                'success': True,
                'application_id': application_id,
                'progress_data': progress_data
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_field_progress(self, application_id: str, field_name: str, field_value: any = None) -> Dict:
        """
        Update progress when a field is completed
        
        Args:
            application_id (str): Application identifier
            field_name (str): Name of completed field
            field_value (any, optional): Field value
            
        Returns:
            dict: Update result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id]
            current_stage_index = progress_data['current_stage']
            current_stage = progress_data['stages'][current_stage_index]
            
            # Add field to completed fields if not already there
            if field_name not in current_stage['completed_fields']:
                current_stage['completed_fields'].append(field_name)
            
            # Calculate stage progress
            required_fields = current_stage['required_fields']
            optional_fields = current_stage['optional_fields']
            completed_fields = current_stage['completed_fields']
            
            # Calculate progress based on required fields
            if required_fields:
                required_completed = sum(1 for field in required_fields if field in completed_fields)
                stage_progress = (required_completed / len(required_fields)) * 100
            else:
                stage_progress = 100.0
            
            # Bonus for optional fields
            if optional_fields:
                optional_completed = sum(1 for field in optional_fields if field in completed_fields)
                optional_bonus = (optional_completed / len(optional_fields)) * 10  # 10% bonus max
                stage_progress = min(stage_progress + optional_bonus, 100.0)
            
            current_stage['progress'] = stage_progress
            
            # Check if stage is complete
            if self._is_stage_complete(current_stage):
                self._complete_current_stage(progress_data)
            
            # Update overall progress
            self._update_overall_progress(progress_data)
            
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'stage_progress': stage_progress,
                'overall_progress': progress_data['overall_progress'],
                'stage_complete': current_stage['status'] == 'completed'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def advance_to_next_stage(self, application_id: str, force: bool = False) -> Dict:
        """
        Advance application to next stage
        
        Args:
            application_id (str): Application identifier
            force (bool): Force advancement even if current stage incomplete
            
        Returns:
            dict: Advancement result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id]
            current_stage_index = progress_data['current_stage']
            current_stage = progress_data['stages'][current_stage_index]
            
            # Check if current stage is complete (unless forced)
            if not force and not self._is_stage_complete(current_stage):
                return {
                    'success': False,
                    'error': 'Current stage is not complete',
                    'missing_requirements': self._get_missing_requirements(current_stage)
                }
            
            # Complete current stage if not already done
            if current_stage['status'] != 'completed':
                self._complete_current_stage(progress_data)
            
            # Check if there are more stages
            if current_stage_index + 1 >= len(progress_data['stages']):
                return {
                    'success': False,
                    'error': 'Application is already at final stage'
                }
            
            # Advance to next stage
            progress_data['current_stage'] = current_stage_index + 1
            next_stage = progress_data['stages'][current_stage_index + 1]
            next_stage['status'] = 'in_progress'
            next_stage['started_at'] = datetime.now().isoformat()
            
            # Update overall progress
            self._update_overall_progress(progress_data)
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'new_stage_index': current_stage_index + 1,
                'new_stage': next_stage,
                'overall_progress': progress_data['overall_progress']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def update_application_status(self, application_id: str, new_status: str, notes: str = None) -> Dict:
        """
        Update application status and sync with progress stages
        
        Args:
            application_id (str): Application identifier
            new_status (str): New application status
            notes (str, optional): Status change notes
            
        Returns:
            dict: Update result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            try:
                status_enum = ApplicationStatus(new_status)
            except ValueError:
                return {
                    'success': False,
                    'error': f'Invalid status: {new_status}'
                }
            
            progress_data = self.application_progress[application_id]
            old_status = progress_data['current_status']
            progress_data['current_status'] = new_status
            
            # Add status change note
            if notes:
                current_stage = progress_data['stages'][progress_data['current_stage']]
                current_stage['notes'].append({
                    'timestamp': datetime.now().isoformat(),
                    'type': 'status_change',
                    'message': f"Status changed from {old_status} to {new_status}: {notes}"
                })
            
            # Sync stages with new status
            self._sync_stages_with_status(progress_data, status_enum)
            
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'old_status': old_status,
                'new_status': new_status,
                'current_stage': progress_data['stages'][progress_data['current_stage']]
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def add_progress_note(self, application_id: str, note: str, note_type: str = 'general') -> Dict:
        """
        Add note to current progress stage
        
        Args:
            application_id (str): Application identifier
            note (str): Note content
            note_type (str): Type of note
            
        Returns:
            dict: Add result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id]
            current_stage = progress_data['stages'][progress_data['current_stage']]
            
            note_entry = {
                'timestamp': datetime.now().isoformat(),
                'type': note_type,
                'message': note
            }
            
            current_stage['notes'].append(note_entry)
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'note_added': note_entry
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def add_progress_blocker(self, application_id: str, blocker: str, severity: str = 'medium') -> Dict:
        """
        Add blocker to current progress stage
        
        Args:
            application_id (str): Application identifier
            blocker (str): Blocker description
            severity (str): Blocker severity (low, medium, high)
            
        Returns:
            dict: Add result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id]
            current_stage = progress_data['stages'][progress_data['current_stage']]
            
            blocker_entry = {
                'id': f"blocker_{int(datetime.now().timestamp())}",
                'timestamp': datetime.now().isoformat(),
                'description': blocker,
                'severity': severity,
                'status': 'active',
                'resolved_at': None
            }
            
            current_stage['blockers'].append(blocker_entry)
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'blocker_added': blocker_entry
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def resolve_progress_blocker(self, application_id: str, blocker_id: str, resolution: str = None) -> Dict:
        """
        Resolve a progress blocker
        
        Args:
            application_id (str): Application identifier
            blocker_id (str): Blocker identifier
            resolution (str, optional): Resolution description
            
        Returns:
            dict: Resolution result
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id]
            
            # Find blocker across all stages
            blocker_found = False
            for stage in progress_data['stages']:
                for blocker in stage['blockers']:
                    if blocker['id'] == blocker_id:
                        blocker['status'] = 'resolved'
                        blocker['resolved_at'] = datetime.now().isoformat()
                        if resolution:
                            blocker['resolution'] = resolution
                        blocker_found = True
                        break
                if blocker_found:
                    break
            
            if not blocker_found:
                return {
                    'success': False,
                    'error': 'Blocker not found'
                }
            
            progress_data['updated_at'] = datetime.now().isoformat()
            
            return {
                'success': True,
                'blocker_resolved': blocker_id
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_application_progress(self, application_id: str) -> Dict:
        """
        Get current progress for application
        
        Args:
            application_id (str): Application identifier
            
        Returns:
            dict: Progress data
        """
        try:
            if application_id not in self.application_progress:
                return {
                    'success': False,
                    'error': 'Application progress not found'
                }
            
            progress_data = self.application_progress[application_id].copy()
            
            # Add calculated fields
            progress_data['time_elapsed'] = self._calculate_time_elapsed(progress_data)
            progress_data['estimated_time_remaining'] = self._calculate_estimated_time_remaining(progress_data)
            progress_data['active_blockers'] = self._get_active_blockers(progress_data)
            progress_data['completion_percentage'] = progress_data['overall_progress']
            
            return {
                'success': True,
                'progress': progress_data
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_progress_summary(self, application_id: str) -> Dict:
        """
        Get condensed progress summary
        
        Args:
            application_id (str): Application identifier
            
        Returns:
            dict: Progress summary
        """
        try:
            result = self.get_application_progress(application_id)
            if not result['success']:
                return result
            
            progress = result['progress']
            current_stage = progress['stages'][progress['current_stage']]
            
            summary = {
                'application_id': application_id,
                'current_status': progress['current_status'],
                'overall_progress': progress['overall_progress'],
                'current_stage': {
                    'title': current_stage['title'],
                    'description': current_stage['description'],
                    'progress': current_stage['progress'],
                    'status': current_stage['status']
                },
                'time_elapsed': progress['time_elapsed'],
                'estimated_time_remaining': progress['estimated_time_remaining'],
                'has_blockers': len(progress['active_blockers']) > 0,
                'next_action': self._get_next_action(progress)
            }
            
            return {
                'success': True,
                'summary': summary
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _calculate_estimated_completion(self, stages: List[Dict]) -> str:
        """
        Calculate estimated completion time
        """
        total_minutes = sum(stage['estimated_duration'] for stage in stages)
        completion_time = datetime.now() + timedelta(minutes=total_minutes)
        return completion_time.isoformat()
    
    def _is_stage_complete(self, stage: Dict) -> bool:
        """
        Check if stage is complete based on completion criteria
        """
        criteria = stage['completion_criteria']
        
        if criteria == 'all_required_fields_completed':
            required_fields = stage['required_fields']
            completed_fields = stage['completed_fields']
            return all(field in completed_fields for field in required_fields)
        
        elif criteria == 'all_required_documents_uploaded':
            # In production, check actual document upload status
            return stage['progress'] >= 100
        
        elif criteria == 'application_submitted':
            return stage['progress'] >= 100
        
        else:
            # For council stages, assume external completion
            return stage['status'] == 'completed'
    
    def _complete_current_stage(self, progress_data: Dict):
        """
        Mark current stage as completed
        """
        current_stage = progress_data['stages'][progress_data['current_stage']]
        current_stage['status'] = 'completed'
        current_stage['completed_at'] = datetime.now().isoformat()
        current_stage['progress'] = 100.0
        
        # Calculate actual duration
        if current_stage['started_at']:
            start_time = datetime.fromisoformat(current_stage['started_at'])
            end_time = datetime.now()
            actual_duration = int((end_time - start_time).total_seconds() / 60)
            current_stage['actual_duration'] = actual_duration
    
    def _update_overall_progress(self, progress_data: Dict):
        """
        Update overall progress based on stage completion
        """
        total_stages = len(progress_data['stages'])
        completed_stages = sum(1 for stage in progress_data['stages'] if stage['status'] == 'completed')
        current_stage_progress = progress_data['stages'][progress_data['current_stage']]['progress']
        
        # Calculate overall progress
        overall_progress = (completed_stages / total_stages) * 100
        overall_progress += (current_stage_progress / total_stages)
        
        progress_data['overall_progress'] = min(overall_progress, 100.0)
    
    def _sync_stages_with_status(self, progress_data: Dict, status: ApplicationStatus):
        """
        Sync stage progress with application status
        """
        # This would contain logic to advance stages based on status changes
        # For now, we'll keep it simple
        pass
    
    def _get_missing_requirements(self, stage: Dict) -> List[str]:
        """
        Get missing requirements for stage completion
        """
        required_fields = stage['required_fields']
        completed_fields = stage['completed_fields']
        return [field for field in required_fields if field not in completed_fields]
    
    def _calculate_time_elapsed(self, progress_data: Dict) -> str:
        """
        Calculate time elapsed since application creation
        """
        created_at = datetime.fromisoformat(progress_data['created_at'])
        elapsed = datetime.now() - created_at
        
        days = elapsed.days
        hours = elapsed.seconds // 3600
        minutes = (elapsed.seconds % 3600) // 60
        
        if days > 0:
            return f"{days} days, {hours} hours"
        elif hours > 0:
            return f"{hours} hours, {minutes} minutes"
        else:
            return f"{minutes} minutes"
    
    def _calculate_estimated_time_remaining(self, progress_data: Dict) -> str:
        """
        Calculate estimated time remaining
        """
        current_stage_index = progress_data['current_stage']
        remaining_stages = progress_data['stages'][current_stage_index:]
        
        total_remaining_minutes = 0
        for stage in remaining_stages:
            if stage['status'] == 'completed':
                continue
            elif stage['status'] == 'in_progress':
                # Estimate remaining time for current stage
                remaining_progress = 100 - stage['progress']
                stage_remaining = (remaining_progress / 100) * stage['estimated_duration']
                total_remaining_minutes += stage_remaining
            else:
                total_remaining_minutes += stage['estimated_duration']
        
        if total_remaining_minutes < 60:
            return f"{int(total_remaining_minutes)} minutes"
        elif total_remaining_minutes < 1440:  # Less than 24 hours
            hours = int(total_remaining_minutes / 60)
            return f"{hours} hours"
        else:
            days = int(total_remaining_minutes / 1440)
            return f"{days} days"
    
    def _get_active_blockers(self, progress_data: Dict) -> List[Dict]:
        """
        Get all active blockers across stages
        """
        active_blockers = []
        for stage in progress_data['stages']:
            for blocker in stage['blockers']:
                if blocker['status'] == 'active':
                    active_blockers.append(blocker)
        return active_blockers
    
    def _get_next_action(self, progress_data: Dict) -> str:
        """
        Get next recommended action for user
        """
        current_stage = progress_data['stages'][progress_data['current_stage']]
        
        if current_stage['status'] == 'completed':
            return "Waiting for next stage to begin"
        
        missing_requirements = self._get_missing_requirements(current_stage)
        if missing_requirements:
            return f"Complete: {', '.join(missing_requirements[:2])}"
        
        if current_stage.get('council_stage'):
            return "Waiting for council review"
        
        return "Continue with current stage"

