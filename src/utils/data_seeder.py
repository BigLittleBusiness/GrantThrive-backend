"""
Data Seeder for GrantThrive Platform
Populates database with real Australian council data and sample grant programs
"""

from datetime import datetime, timedelta
import uuid
import random

# Import all models first to ensure relationships are properly defined
from ..models.user import User, UserRole, UserStatus, db
from ..models.grant import Grant
from ..models.application import Application
from ..data.australian_councils import (
    AUSTRALIAN_COUNCILS, 
    NEW_ZEALAND_COUNCILS, 
    GRANT_PROGRAM_TEMPLATES,
    SAMPLE_APPLICATIONS
)

def seed_database():
    """Seed the database with real Australian council data"""
    
    print("Starting database seeding...")
    
    # Clear existing data (for development only)
    db.session.query(Application).delete()
    db.session.query(Grant).delete()
    db.session.query(User).delete()
    db.session.commit()
    
    # Seed Council Users
    council_users = []
    for council in AUSTRALIAN_COUNCILS[:10]:  # Seed first 10 councils
        # Create council admin
        admin_user = User(
            email=f"admin@{council['email_domain']}",
            password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",  # password: admin123
            first_name="Council",
            last_name="Administrator",
            role=UserRole.COUNCIL_ADMIN,
            organization_name=council['name'],
            phone=council['phone'],
            address_line1=council['address'],
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            profile_data={
                'council_id': council['id'],
                'council_tier': council['tier'],
                'state': council['state'],
                'population': council['population'],
                'grant_budget': council['grant_budget_annual']
            }
        )
        db.session.add(admin_user)
        council_users.append(admin_user)
        
        # Create council staff member
        staff_user = User(
            id=str(uuid.uuid4()),
            email=f"grants@{council['email_domain']}",
            password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",  # password: staff123
            first_name="Grants",
            last_name="Officer",
            role="council_staff",
            organization=council['name'],
            phone=council['phone'],
            address=council['address'],
            is_verified=True,
            created_at=datetime.utcnow(),
            profile_data={
                'council_id': council['id'],
                'department': 'Community Services',
                'position': 'Grants Officer'
            }
        )
        db.session.add(staff_user)
        council_users.append(staff_user)
    
    # Seed New Zealand Councils
    for council in NEW_ZEALAND_COUNCILS:
        admin_user = User(
            id=str(uuid.uuid4()),
            email=f"admin@{council['email_domain']}",
            password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",
            first_name="Council",
            last_name="Administrator",
            role="council_admin",
            organization=council['name'],
            phone=council['phone'],
            address=council['address'],
            is_verified=True,
            created_at=datetime.utcnow(),
            profile_data={
                'council_id': council['id'],
                'council_tier': council['tier'],
                'country': 'NZ',
                'state': council['state'],
                'population': council['population'],
                'grant_budget': council['grant_budget_annual']
            }
        )
        db.session.add(admin_user)
        council_users.append(admin_user)
    
    # Seed Community Users
    community_users = []
    community_orgs = [
        {
            'name': 'Emma Thompson',
            'org': 'Community Arts Collective',
            'email': 'emma@communityarts.org.au',
            'type': 'Arts Organization'
        },
        {
            'name': 'Michael Rodriguez',
            'org': 'Neighborhood Alliance',
            'email': 'michael@neighborhoodalliance.org.au',
            'type': 'Community Group'
        },
        {
            'name': 'Sarah Kim',
            'org': 'Youth Empowerment Network',
            'email': 'sarah@youthempowerment.org.au',
            'type': 'Youth Organization'
        },
        {
            'name': 'David Chen',
            'org': 'Green Future Foundation',
            'email': 'david@greenfuture.org.au',
            'type': 'Environmental Group'
        },
        {
            'name': 'Lisa Patel',
            'org': 'Cultural Diversity Council',
            'email': 'lisa@culturaldiversity.org.au',
            'type': 'Multicultural Organization'
        },
        {
            'name': 'James Wilson',
            'org': 'Local Business Network',
            'email': 'james@localbusiness.org.au',
            'type': 'Business Association'
        }
    ]
    
    for org_data in community_orgs:
        user = User(
            id=str(uuid.uuid4()),
            email=org_data['email'],
            password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",  # password: community123
            first_name=org_data['name'].split()[0],
            last_name=org_data['name'].split()[1],
            role="community_member",
            organization=org_data['org'],
            phone=f"+61 {random.randint(2, 8)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
            is_verified=True,
            created_at=datetime.utcnow(),
            profile_data={
                'organization_type': org_data['type'],
                'abn': f"{random.randint(10, 99)} {random.randint(100, 999)} {random.randint(100, 999)} {random.randint(100, 999)}",
                'established_year': random.randint(2010, 2020)
            }
        )
        db.session.add(user)
        community_users.append(user)
    
    # Seed Professional Consultants
    consultant_users = []
    consultants = [
        {
            'name': 'Dr. Amanda Foster',
            'company': 'Grant Success Partners',
            'email': 'amanda@grantsuccess.com.au',
            'specialty': 'Community Development'
        },
        {
            'name': 'Robert Zhang',
            'company': 'Strategic Funding Solutions',
            'email': 'robert@strategicfunding.com.au',
            'specialty': 'Environmental Grants'
        },
        {
            'name': 'Jennifer Martinez',
            'company': 'Arts Funding Consultancy',
            'email': 'jennifer@artsfunding.com.au',
            'specialty': 'Arts & Culture'
        }
    ]
    
    for consultant_data in consultants:
        user = User(
            id=str(uuid.uuid4()),
            email=consultant_data['email'],
            password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",  # password: consultant123
            first_name=consultant_data['name'].split()[1] if 'Dr.' in consultant_data['name'] else consultant_data['name'].split()[0],
            last_name=consultant_data['name'].split()[-1],
            role="professional_consultant",
            organization=consultant_data['company'],
            phone=f"+61 {random.randint(2, 8)} {random.randint(1000, 9999)} {random.randint(1000, 9999)}",
            is_verified=True,
            created_at=datetime.utcnow(),
            profile_data={
                'specialty': consultant_data['specialty'],
                'years_experience': random.randint(5, 20),
                'success_rate': random.randint(75, 95),
                'certifications': ['Certified Grant Professional', 'Project Management Professional']
            }
        )
        db.session.add(user)
        consultant_users.append(user)
    
    db.session.commit()
    print(f"Seeded {len(council_users)} council users, {len(community_users)} community users, {len(consultant_users)} consultants")
    
    # Seed Grant Programs
    grants = []
    for i, council_user in enumerate(council_users[:5]):  # Create grants for first 5 councils
        council_data = AUSTRALIAN_COUNCILS[i // 2]  # Each council has 2 users (admin + staff)
        
        for template in GRANT_PROGRAM_TEMPLATES:
            # Adjust amounts based on council tier
            tier_multiplier = {1: 1.5, 2: 1.0, 3: 0.7, 4: 0.5}
            multiplier = tier_multiplier.get(council_data['tier'], 1.0)
            
            grant = Grant(
                id=str(uuid.uuid4()),
                title=f"{council_data['name']} - {template['title']}",
                description=template['description'],
                category=template['category'],
                min_amount=int(template['min_amount'] * multiplier),
                max_amount=int(template['max_amount'] * multiplier),
                total_funding=int(template['max_amount'] * multiplier * random.randint(5, 15)),
                application_deadline=datetime.utcnow() + timedelta(days=random.randint(30, 90)),
                project_start_date=datetime.utcnow() + timedelta(days=random.randint(100, 150)),
                project_end_date=datetime.utcnow() + timedelta(days=random.randint(200, 400)),
                status='open',
                created_by=council_user.id,
                created_at=datetime.utcnow(),
                eligibility_criteria=template['eligibility_criteria'],
                assessment_criteria=template['assessment_criteria'],
                required_documents=template['required_documents'],
                application_form_fields=[
                    {
                        'id': 'project_title',
                        'label': 'Project Title',
                        'type': 'text',
                        'required': True,
                        'max_length': 100
                    },
                    {
                        'id': 'project_description',
                        'label': 'Project Description',
                        'type': 'textarea',
                        'required': True,
                        'max_length': 2000
                    },
                    {
                        'id': 'requested_amount',
                        'label': 'Requested Amount',
                        'type': 'number',
                        'required': True,
                        'min': template['min_amount'],
                        'max': template['max_amount']
                    },
                    {
                        'id': 'project_duration',
                        'label': 'Project Duration',
                        'type': 'text',
                        'required': True
                    },
                    {
                        'id': 'expected_participants',
                        'label': 'Expected Participants/Beneficiaries',
                        'type': 'number',
                        'required': True
                    },
                    {
                        'id': 'community_benefit',
                        'label': 'Community Benefit',
                        'type': 'textarea',
                        'required': True,
                        'max_length': 1000
                    },
                    {
                        'id': 'sustainability_plan',
                        'label': 'Sustainability Plan',
                        'type': 'textarea',
                        'required': True,
                        'max_length': 1000
                    }
                ],
                council_data={
                    'council_id': council_data['id'],
                    'council_name': council_data['name'],
                    'state': council_data['state'],
                    'tier': council_data['tier']
                }
            )
            db.session.add(grant)
            grants.append(grant)
    
    db.session.commit()
    print(f"Seeded {len(grants)} grant programs")
    
    # Seed Applications
    applications = []
    for i, sample_app in enumerate(SAMPLE_APPLICATIONS):
        # Find matching grant and applicant
        matching_grants = [g for g in grants if sample_app['grant_program'] in g.category.lower().replace(' ', '-')]
        if not matching_grants:
            continue
            
        grant = random.choice(matching_grants)
        applicant = random.choice(community_users)
        
        application = Application(
            id=str(uuid.uuid4()),
            grant_id=grant.id,
            applicant_id=applicant.id,
            project_title=sample_app['project_title'],
            project_description=sample_app['project_description'],
            requested_amount=sample_app['requested_amount'],
            status=sample_app['status'],
            submitted_at=datetime.strptime(sample_app['submission_date'], '%Y-%m-%d'),
            created_at=datetime.strptime(sample_app['submission_date'], '%Y-%m-%d'),
            application_data={
                'project_duration': sample_app['project_duration'],
                'expected_participants': sample_app['expected_participants'],
                'community_benefit': sample_app['community_benefit'],
                'sustainability_plan': sample_app['sustainability_plan']
            },
            priority='high' if sample_app['requested_amount'] > 30000 else 'medium',
            assigned_reviewers=[],
            documents=[],
            review_data={},
            review_comments=[]
        )
        
        # Add some review data for approved applications
        if sample_app['status'] == 'approved':
            application.final_score = random.randint(70, 90)
            application.reviewed_at = datetime.utcnow() - timedelta(days=random.randint(1, 10))
            application.reviewed_by = random.choice([u.id for u in council_users if u.role == 'council_admin'])
            application.review_data = {
                'final_review': {
                    'scores': {
                        'impact': random.randint(7, 10),
                        'feasibility': random.randint(7, 9),
                        'budget': random.randint(6, 9),
                        'sustainability': random.randint(6, 8),
                        'innovation': random.randint(5, 8)
                    },
                    'comments': 'Excellent project with strong community benefit and clear implementation plan.',
                    'recommendation': 'approve'
                }
            }
        
        db.session.add(application)
        applications.append(application)
    
    # Add some additional random applications
    for _ in range(15):
        grant = random.choice(grants)
        applicant = random.choice(community_users)
        
        project_titles = [
            'Community Health Initiative',
            'Digital Literacy Program',
            'Local Heritage Project',
            'Youth Leadership Development',
            'Environmental Education Program',
            'Small Business Mentoring',
            'Cultural Exchange Program',
            'Disability Support Services',
            'Senior Citizens Engagement',
            'Indigenous Cultural Program'
        ]
        
        application = Application(
            id=str(uuid.uuid4()),
            grant_id=grant.id,
            applicant_id=applicant.id,
            project_title=random.choice(project_titles),
            project_description=f"A comprehensive program designed to benefit the local community through innovative approaches and sustainable outcomes. This project will engage participants in meaningful activities that create lasting positive impact.",
            requested_amount=random.randint(grant.min_amount, grant.max_amount),
            status=random.choice(['submitted', 'under_review', 'under_review', 'approved', 'declined']),
            submitted_at=datetime.utcnow() - timedelta(days=random.randint(1, 60)),
            created_at=datetime.utcnow() - timedelta(days=random.randint(1, 60)),
            application_data={
                'project_duration': f"{random.randint(6, 24)} months",
                'expected_participants': random.randint(20, 500),
                'community_benefit': 'Significant positive impact on local community',
                'sustainability_plan': 'Long-term sustainability through community ownership and ongoing support'
            },
            priority=random.choice(['high', 'medium', 'low']),
            assigned_reviewers=[],
            documents=[],
            review_data={},
            review_comments=[]
        )
        
        db.session.add(application)
        applications.append(application)
    
    db.session.commit()
    print(f"Seeded {len(applications)} applications")
    
    print("Database seeding completed successfully!")
    return {
        'councils': len(AUSTRALIAN_COUNCILS) + len(NEW_ZEALAND_COUNCILS),
        'users': len(council_users) + len(community_users) + len(consultant_users),
        'grants': len(grants),
        'applications': len(applications)
    }

def seed_demo_data():
    """Seed minimal demo data for testing"""
    
    # Create demo users with known credentials
    demo_users = [
        {
            'email': 'sarah.johnson@melbourne.vic.gov.au',
            'password': 'demo123',
            'first_name': 'Sarah',
            'last_name': 'Johnson',
            'role': 'council_admin',
            'organization': 'City of Melbourne'
        },
        {
            'email': 'michael.chen@melbourne.vic.gov.au',
            'password': 'demo123',
            'first_name': 'Michael',
            'last_name': 'Chen',
            'role': 'council_staff',
            'organization': 'City of Melbourne'
        },
        {
            'email': 'emma.thompson@communityarts.org.au',
            'password': 'demo123',
            'first_name': 'Emma',
            'last_name': 'Thompson',
            'role': 'community_member',
            'organization': 'Community Arts Collective'
        },
        {
            'email': 'david.wilson@grantsuccess.com.au',
            'password': 'demo123',
            'first_name': 'David',
            'last_name': 'Wilson',
            'role': 'professional_consultant',
            'organization': 'Grant Success Partners'
        }
    ]
    
    for user_data in demo_users:
        existing_user = User.query.filter_by(email=user_data['email']).first()
        if not existing_user:
            user = User(
                id=str(uuid.uuid4()),
                email=user_data['email'],
                password_hash="$2b$12$LQv3c1yqBwEHFl5ePEjNNONHNONHNONHNONHNONHNONHNONHNONH",
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                role=user_data['role'],
                organization=user_data['organization'],
                is_verified=True,
                created_at=datetime.utcnow()
            )
            db.session.add(user)
    
    db.session.commit()
    print("Demo data seeded successfully!")

if __name__ == '__main__':
    seed_database()

