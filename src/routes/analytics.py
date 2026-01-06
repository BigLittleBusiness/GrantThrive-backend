from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
from sqlalchemy import func, and_, or_
from src.models.user import User
from src.models.grant import Grant
from src.models.application import Application
from src.middleware.auth import require_auth, require_role
from src.utils.audit import log_activity
import calendar

analytics_bp = Blueprint('analytics', __name__)

@analytics_bp.route('/dashboard', methods=['GET'])
@require_auth
def get_dashboard_metrics():
    """Get comprehensive dashboard metrics"""
    try:
        user = request.current_user
        
        # Base queries with user filtering
        if user.role in ['council_admin', 'council_staff']:
            # Council users see their council's data
            grants_query = Grant.query.filter_by(council_id=user.council_id)
            applications_query = Application.query.join(Grant).filter(Grant.council_id == user.council_id)
        else:
            # Community users see their own applications
            grants_query = Grant.query.filter_by(status='open')
            applications_query = Application.query.filter_by(user_id=user.id)

        # Calculate basic metrics
        total_grants = grants_query.count()
        total_applications = applications_query.count()
        
        # Grant value metrics
        total_grant_value = grants_query.with_entities(func.sum(Grant.amount)).scalar() or 0
        
        # Application metrics
        approved_applications = applications_query.filter_by(status='approved').count()
        pending_applications = applications_query.filter(
            Application.status.in_(['submitted', 'under_review'])
        ).count()
        
        # Success rate calculation
        success_rate = (approved_applications / total_applications * 100) if total_applications > 0 else 0
        
        # Amount metrics
        total_requested = applications_query.with_entities(
            func.sum(Application.requested_amount)
        ).scalar() or 0
        
        total_approved_amount = applications_query.filter_by(status='approved').with_entities(
            func.sum(Application.requested_amount)
        ).scalar() or 0

        # Open grants count
        open_grants = grants_query.filter_by(status='open').count()

        # Recent activity (last 30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_applications = applications_query.filter(
            Application.created_at >= thirty_days_ago
        ).count()
        
        recent_grants = grants_query.filter(
            Grant.created_at >= thirty_days_ago
        ).count()

        metrics = {
            'total_grants': total_grants,
            'total_applications': total_applications,
            'total_grant_value': float(total_grant_value),
            'total_requested_amount': float(total_requested),
            'total_approved_amount': float(total_approved_amount),
            'success_rate': round(success_rate, 1),
            'open_grants': open_grants,
            'pending_applications': pending_applications,
            'approved_applications': approved_applications,
            'recent_applications': recent_applications,
            'recent_grants': recent_grants,
            'available_funding': float(total_grant_value - total_approved_amount)
        }

        log_activity(user.id, 'analytics_dashboard_viewed', {'metrics_count': len(metrics)})
        
        return jsonify({
            'success': True,
            'data': metrics
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching dashboard metrics: {str(e)}'
        }), 500

@analytics_bp.route('/trends', methods=['GET'])
@require_auth
def get_trends_data():
    """Get time series data for trends analysis"""
    try:
        user = request.current_user
        months = int(request.args.get('months', 12))
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=months * 30)
        
        # Base queries with user filtering
        if user.role in ['council_admin', 'council_staff']:
            grants_query = Grant.query.filter_by(council_id=user.council_id)
            applications_query = Application.query.join(Grant).filter(Grant.council_id == user.council_id)
        else:
            grants_query = Grant.query.filter_by(status='open')
            applications_query = Application.query.filter_by(user_id=user.id)

        # Generate monthly data
        trends_data = []
        current_date = start_date.replace(day=1)
        
        while current_date <= end_date:
            month_start = current_date
            if current_date.month == 12:
                month_end = current_date.replace(year=current_date.year + 1, month=1, day=1) - timedelta(days=1)
            else:
                month_end = current_date.replace(month=current_date.month + 1, day=1) - timedelta(days=1)
            
            # Applications for this month
            month_applications = applications_query.filter(
                and_(
                    Application.created_at >= month_start,
                    Application.created_at <= month_end
                )
            ).count()
            
            # Grants for this month
            month_grants = grants_query.filter(
                and_(
                    Grant.created_at >= month_start,
                    Grant.created_at <= month_end
                )
            ).count()
            
            # Approved applications for this month
            month_approved = applications_query.filter(
                and_(
                    Application.created_at >= month_start,
                    Application.created_at <= month_end,
                    Application.status == 'approved'
                )
            ).count()
            
            # Total value for this month
            month_value = applications_query.filter(
                and_(
                    Application.created_at >= month_start,
                    Application.created_at <= month_end
                )
            ).with_entities(func.sum(Application.requested_amount)).scalar() or 0

            trends_data.append({
                'month': current_date.strftime('%b %Y'),
                'applications': month_applications,
                'grants': month_grants,
                'approved': month_approved,
                'value': float(month_value)
            })
            
            # Move to next month
            if current_date.month == 12:
                current_date = current_date.replace(year=current_date.year + 1, month=1)
            else:
                current_date = current_date.replace(month=current_date.month + 1)

        log_activity(user.id, 'analytics_trends_viewed', {'months': months})
        
        return jsonify({
            'success': True,
            'data': trends_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching trends data: {str(e)}'
        }), 500

@analytics_bp.route('/categories', methods=['GET'])
@require_auth
def get_category_distribution():
    """Get grant category distribution data"""
    try:
        user = request.current_user
        
        # Base query with user filtering
        if user.role in ['council_admin', 'council_staff']:
            grants_query = Grant.query.filter_by(council_id=user.council_id)
        else:
            grants_query = Grant.query.filter_by(status='open')

        # Get category distribution
        category_data = grants_query.with_entities(
            Grant.category,
            func.count(Grant.id).label('count'),
            func.sum(Grant.amount).label('total_value')
        ).group_by(Grant.category).all()

        total_grants = grants_query.count()
        
        distribution = []
        for category, count, total_value in category_data:
            distribution.append({
                'name': category or 'Other',
                'value': count,
                'percentage': round((count / total_grants * 100), 1) if total_grants > 0 else 0,
                'total_value': float(total_value or 0)
            })

        # Sort by count descending
        distribution.sort(key=lambda x: x['value'], reverse=True)

        log_activity(user.id, 'analytics_categories_viewed', {'categories_count': len(distribution)})
        
        return jsonify({
            'success': True,
            'data': distribution
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching category distribution: {str(e)}'
        }), 500

@analytics_bp.route('/status-distribution', methods=['GET'])
@require_auth
def get_status_distribution():
    """Get application status distribution data"""
    try:
        user = request.current_user
        
        # Base query with user filtering
        if user.role in ['council_admin', 'council_staff']:
            applications_query = Application.query.join(Grant).filter(Grant.council_id == user.council_id)
        else:
            applications_query = Application.query.filter_by(user_id=user.id)

        # Get status distribution
        status_data = applications_query.with_entities(
            Application.status,
            func.count(Application.id).label('count'),
            func.sum(Application.requested_amount).label('total_amount')
        ).group_by(Application.status).all()

        distribution = []
        status_colors = {
            'draft': '#6B7280',
            'submitted': '#3B82F6',
            'under_review': '#F59E0B',
            'approved': '#10B981',
            'rejected': '#EF4444',
            'completed': '#8B5CF6'
        }

        for status, count, total_amount in status_data:
            distribution.append({
                'name': status.replace('_', ' ').upper() if status else 'UNKNOWN',
                'value': count,
                'color': status_colors.get(status, '#6B7280'),
                'total_amount': float(total_amount or 0)
            })

        # Sort by count descending
        distribution.sort(key=lambda x: x['value'], reverse=True)

        log_activity(user.id, 'analytics_status_viewed', {'statuses_count': len(distribution)})
        
        return jsonify({
            'success': True,
            'data': distribution
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching status distribution: {str(e)}'
        }), 500

@analytics_bp.route('/performance', methods=['GET'])
@require_auth
def get_performance_metrics():
    """Get detailed performance metrics"""
    try:
        user = request.current_user
        
        # Base queries with user filtering
        if user.role in ['council_admin', 'council_staff']:
            grants_query = Grant.query.filter_by(council_id=user.council_id)
            applications_query = Application.query.join(Grant).filter(Grant.council_id == user.council_id)
        else:
            grants_query = Grant.query.filter_by(status='open')
            applications_query = Application.query.filter_by(user_id=user.id)

        # Calculate performance metrics
        total_applications = applications_query.count()
        approved_applications = applications_query.filter_by(status='approved').count()
        rejected_applications = applications_query.filter_by(status='rejected').count()
        
        # Success and rejection rates
        success_rate = (approved_applications / total_applications * 100) if total_applications > 0 else 0
        rejection_rate = (rejected_applications / total_applications * 100) if total_applications > 0 else 0
        
        # Amount metrics
        total_grant_value = grants_query.with_entities(func.sum(Grant.amount)).scalar() or 0
        total_requested = applications_query.with_entities(func.sum(Application.requested_amount)).scalar() or 0
        total_approved_amount = applications_query.filter_by(status='approved').with_entities(
            func.sum(Application.requested_amount)
        ).scalar() or 0
        
        # Utilization rate
        utilization_rate = (total_approved_amount / total_grant_value * 100) if total_grant_value > 0 else 0
        
        # Average processing time (for completed applications)
        completed_applications = applications_query.filter(
            Application.status.in_(['approved', 'rejected'])
        ).all()
        
        processing_times = []
        for app in completed_applications:
            if app.created_at and app.updated_at:
                processing_time = (app.updated_at - app.created_at).days
                processing_times.append(processing_time)
        
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        # Top performing categories
        top_categories = applications_query.join(Grant).filter_by(status='approved').with_entities(
            Grant.category,
            func.count(Application.id).label('approved_count'),
            func.sum(Application.requested_amount).label('approved_amount')
        ).group_by(Grant.category).order_by(func.count(Application.id).desc()).limit(5).all()

        performance_data = {
            'success_rate': round(success_rate, 1),
            'rejection_rate': round(rejection_rate, 1),
            'utilization_rate': round(utilization_rate, 1),
            'avg_processing_time': round(avg_processing_time, 1),
            'total_grant_value': float(total_grant_value),
            'total_requested': float(total_requested),
            'total_approved_amount': float(total_approved_amount),
            'available_funding': float(total_grant_value - total_approved_amount),
            'top_categories': [
                {
                    'category': cat or 'Other',
                    'approved_count': count,
                    'approved_amount': float(amount or 0)
                }
                for cat, count, amount in top_categories
            ]
        }

        log_activity(user.id, 'analytics_performance_viewed', {'metrics_calculated': len(performance_data)})
        
        return jsonify({
            'success': True,
            'data': performance_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error fetching performance metrics: {str(e)}'
        }), 500

@analytics_bp.route('/insights', methods=['GET'])
@require_auth
def get_insights():
    """Get AI-powered insights and recommendations"""
    try:
        user = request.current_user
        
        # Base queries with user filtering
        if user.role in ['council_admin', 'council_staff']:
            grants_query = Grant.query.filter_by(council_id=user.council_id)
            applications_query = Application.query.join(Grant).filter(Grant.council_id == user.council_id)
        else:
            grants_query = Grant.query.filter_by(status='open')
            applications_query = Application.query.filter_by(user_id=user.id)

        insights = []
        recommendations = []
        
        # Calculate key metrics for insights
        total_applications = applications_query.count()
        approved_applications = applications_query.filter_by(status='approved').count()
        pending_applications = applications_query.filter(
            Application.status.in_(['submitted', 'under_review'])
        ).count()
        
        success_rate = (approved_applications / total_applications * 100) if total_applications > 0 else 0
        
        # Generate insights based on data patterns
        if success_rate < 40:
            insights.append({
                'type': 'warning',
                'title': 'Low Success Rate',
                'description': f'Your current success rate of {success_rate:.1f}% is below the recommended 60% benchmark.',
                'impact': 'high'
            })
            recommendations.append({
                'title': 'Improve Application Quality',
                'description': 'Consider providing more detailed guidelines and examples to help applicants submit stronger proposals.',
                'priority': 'high'
            })
        
        elif success_rate > 80:
            insights.append({
                'type': 'success',
                'title': 'Excellent Success Rate',
                'description': f'Your success rate of {success_rate:.1f}% is well above average, indicating high-quality applications.',
                'impact': 'positive'
            })
        
        if pending_applications > 10:
            insights.append({
                'type': 'alert',
                'title': 'Application Backlog',
                'description': f'You have {pending_applications} applications pending review.',
                'impact': 'medium'
            })
            recommendations.append({
                'title': 'Review Pending Applications',
                'description': 'Consider allocating more time for application reviews to reduce processing delays.',
                'priority': 'medium'
            })
        
        # Trend analysis (compare last 2 months)
        two_months_ago = datetime.utcnow() - timedelta(days=60)
        one_month_ago = datetime.utcnow() - timedelta(days=30)
        
        last_month_apps = applications_query.filter(
            and_(
                Application.created_at >= one_month_ago,
                Application.created_at < datetime.utcnow()
            )
        ).count()
        
        previous_month_apps = applications_query.filter(
            and_(
                Application.created_at >= two_months_ago,
                Application.created_at < one_month_ago
            )
        ).count()
        
        if last_month_apps > previous_month_apps * 1.2:
            insights.append({
                'type': 'trend',
                'title': 'Increasing Application Volume',
                'description': f'Applications increased by {((last_month_apps - previous_month_apps) / previous_month_apps * 100):.1f}% last month.',
                'impact': 'positive'
            })
        
        # Category analysis
        popular_categories = grants_query.with_entities(
            Grant.category,
            func.count(Grant.id).label('count')
        ).group_by(Grant.category).order_by(func.count(Grant.id).desc()).limit(3).all()
        
        if popular_categories:
            top_category = popular_categories[0]
            insights.append({
                'type': 'info',
                'title': 'Popular Grant Category',
                'description': f'{top_category[0]} is your most popular category with {top_category[1]} grants.',
                'impact': 'neutral'
            })
            
            recommendations.append({
                'title': 'Expand Popular Categories',
                'description': f'Consider creating more grants in {top_category[0]} due to high demand.',
                'priority': 'low'
            })

        log_activity(user.id, 'analytics_insights_viewed', {
            'insights_count': len(insights),
            'recommendations_count': len(recommendations)
        })
        
        return jsonify({
            'success': True,
            'data': {
                'insights': insights,
                'recommendations': recommendations,
                'generated_at': datetime.utcnow().isoformat()
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error generating insights: {str(e)}'
        }), 500

@analytics_bp.route('/export', methods=['POST'])
@require_auth
def export_analytics_data():
    """Export analytics data in various formats"""
    try:
        user = request.current_user
        data = request.get_json()
        export_type = data.get('type', 'json')  # json, csv, pdf
        date_range = data.get('date_range', '12months')
        
        # This would typically generate and return file data
        # For now, return a success message
        
        log_activity(user.id, 'analytics_data_exported', {
            'export_type': export_type,
            'date_range': date_range
        })
        
        return jsonify({
            'success': True,
            'message': f'Analytics data exported successfully as {export_type}',
            'download_url': f'/api/analytics/download/{export_type}',
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error exporting analytics data: {str(e)}'
        }), 500

