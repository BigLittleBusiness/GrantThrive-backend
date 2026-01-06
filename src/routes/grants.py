from flask import Blueprint, request, jsonify, current_app
from src.models.user import db, User
from src.models.grant import Grant, GrantStatus, GrantCategory
from src.routes.auth import verify_token
from datetime import datetime
import json

grants_bp = Blueprint('grants', __name__)

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

@grants_bp.route('/grants', methods=['GET'])
def get_grants():
    """Get all grants with filtering and pagination"""
    try:
        # Query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        category = request.args.get('category')
        status = request.args.get('status')
        search = request.args.get('search')
        min_funding = request.args.get('min_funding', type=float)
        max_funding = request.args.get('max_funding', type=float)
        
        # Build query
        query = Grant.query
        
        # Apply filters
        if category:
            try:
                category_enum = GrantCategory(category)
                query = query.filter(Grant.category == category_enum)
            except ValueError:
                pass
        
        if status:
            try:
                status_enum = GrantStatus(status)
                query = query.filter(Grant.status == status_enum)
            except ValueError:
                pass
        
        if search:
            query = query.filter(
                Grant.title.contains(search) |
                Grant.description.contains(search) |
                Grant.short_description.contains(search)
            )
        
        if min_funding:
            query = query.filter(Grant.funding_amount >= min_funding)
        
        if max_funding:
            query = query.filter(Grant.funding_amount <= max_funding)
        
        # Order by creation date (newest first)
        query = query.order_by(Grant.created_at.desc())
        
        # Paginate
        grants = query.paginate(
            page=page, 
            per_page=per_page, 
            error_out=False
        )
        
        return jsonify({
            'grants': [grant.to_dict() for grant in grants.items],
            'pagination': {
                'page': grants.page,
                'pages': grants.pages,
                'per_page': grants.per_page,
                'total': grants.total,
                'has_next': grants.has_next,
                'has_prev': grants.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@grants_bp.route('/grants/<int:grant_id>', methods=['GET'])
def get_grant(grant_id):
    """Get specific grant by ID"""
    try:
        grant = Grant.query.get_or_404(grant_id)
        
        # Increment view count
        grant.view_count += 1
        db.session.commit()
        
        grant_data = grant.to_dict()
        
        # Add creator information
        if grant.created_by:
            grant_data['created_by'] = {
                'name': grant.created_by.full_name,
                'organization': grant.created_by.organization_name
            }
        
        return jsonify(grant_data), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@grants_bp.route('/grants', methods=['POST'])
@require_auth
def create_grant():
    """Create new grant (admin only)"""
    try:
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['title', 'description', 'funding_amount', 'close_date', 'category']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400
        
        # Parse dates
        try:
            close_date = datetime.fromisoformat(data['close_date'].replace('Z', '+00:00'))
            open_date = datetime.fromisoformat(data.get('open_date', datetime.utcnow().isoformat()).replace('Z', '+00:00'))
        except ValueError:
            return jsonify({'error': 'Invalid date format'}), 400
        
        # Validate category
        try:
            category = GrantCategory(data['category'])
        except ValueError:
            return jsonify({'error': 'Invalid category'}), 400
        
        # Create grant
        grant = Grant(
            title=data['title'],
            description=data['description'],
            short_description=data.get('short_description'),
            funding_amount=data['funding_amount'],
            min_funding=data.get('min_funding'),
            max_funding=data.get('max_funding'),
            open_date=open_date,
            close_date=close_date,
            category=category,
            status=GrantStatus(data.get('status', 'draft')),
            eligibility_criteria=data.get('eligibility_criteria'),
            required_documents=json.dumps(data.get('required_documents', [])),
            organization_id=request.current_user.id,
            contact_email=data.get('contact_email', request.current_user.email),
            contact_phone=data.get('contact_phone'),
            tags=json.dumps(data.get('tags', [])),
            location_restrictions=data.get('location_restrictions'),
            website_url=data.get('website_url')
        )
        
        db.session.add(grant)
        db.session.commit()
        
        return jsonify({
            'message': 'Grant created successfully',
            'grant': grant.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@grants_bp.route('/grants/<int:grant_id>', methods=['PUT'])
@require_auth
def update_grant(grant_id):
    """Update existing grant (admin only)"""
    try:
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        grant = Grant.query.get_or_404(grant_id)
        
        # Check if user can edit this grant
        if grant.organization_id != request.current_user.id and not request.current_user.role.value == 'system_admin':
            return jsonify({'error': 'Permission denied'}), 403
        
        data = request.get_json()
        
        # Update fields
        if 'title' in data:
            grant.title = data['title']
        if 'description' in data:
            grant.description = data['description']
        if 'short_description' in data:
            grant.short_description = data['short_description']
        if 'funding_amount' in data:
            grant.funding_amount = data['funding_amount']
        if 'min_funding' in data:
            grant.min_funding = data['min_funding']
        if 'max_funding' in data:
            grant.max_funding = data['max_funding']
        if 'close_date' in data:
            grant.close_date = datetime.fromisoformat(data['close_date'].replace('Z', '+00:00'))
        if 'open_date' in data:
            grant.open_date = datetime.fromisoformat(data['open_date'].replace('Z', '+00:00'))
        if 'category' in data:
            grant.category = GrantCategory(data['category'])
        if 'status' in data:
            grant.status = GrantStatus(data['status'])
        if 'eligibility_criteria' in data:
            grant.eligibility_criteria = data['eligibility_criteria']
        if 'required_documents' in data:
            grant.required_documents = json.dumps(data['required_documents'])
        if 'contact_email' in data:
            grant.contact_email = data['contact_email']
        if 'contact_phone' in data:
            grant.contact_phone = data['contact_phone']
        if 'tags' in data:
            grant.tags = json.dumps(data['tags'])
        if 'location_restrictions' in data:
            grant.location_restrictions = data['location_restrictions']
        if 'website_url' in data:
            grant.website_url = data['website_url']
        
        grant.updated_at = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'message': 'Grant updated successfully',
            'grant': grant.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@grants_bp.route('/grants/<int:grant_id>', methods=['DELETE'])
@require_auth
def delete_grant(grant_id):
    """Delete grant (admin only)"""
    try:
        if not request.current_user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        
        grant = Grant.query.get_or_404(grant_id)
        
        # Check if user can delete this grant
        if grant.organization_id != request.current_user.id and not request.current_user.role.value == 'system_admin':
            return jsonify({'error': 'Permission denied'}), 403
        
        db.session.delete(grant)
        db.session.commit()
        
        return jsonify({'message': 'Grant deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@grants_bp.route('/grants/categories', methods=['GET'])
def get_categories():
    """Get all grant categories"""
    categories = [{'value': cat.value, 'label': cat.value.replace('_', ' ').title()} 
                 for cat in GrantCategory]
    return jsonify({'categories': categories}), 200

@grants_bp.route('/grants/stats', methods=['GET'])
def get_grant_stats():
    """Get grant statistics"""
    try:
        total_grants = Grant.query.count()
        open_grants = Grant.query.filter(Grant.status == GrantStatus.OPEN).count()
        total_funding = db.session.query(db.func.sum(Grant.funding_amount)).scalar() or 0
        
        # Category breakdown
        category_stats = db.session.query(
            Grant.category, 
            db.func.count(Grant.id)
        ).group_by(Grant.category).all()
        
        category_breakdown = {cat.value: count for cat, count in category_stats}
        
        return jsonify({
            'total_grants': total_grants,
            'open_grants': open_grants,
            'total_funding': total_funding,
            'category_breakdown': category_breakdown
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

