#!/usr/bin/env python3
"""
Script to seed GrantThrive database with real Australian council data
"""

import os
import sys

# Add the src directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from flask import Flask
from src.models.user import db
from src.utils.data_seeder import seed_database, seed_demo_data

def create_app():
    """Create Flask app for seeding"""
    app = Flask(__name__)
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'src', 'database', 'app.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Check command line arguments
        if len(sys.argv) > 1 and sys.argv[1] == '--demo':
            print("Seeding demo data only...")
            seed_demo_data()
        else:
            print("Seeding full database with Australian council data...")
            result = seed_database()
            print(f"\nSeeding Summary:")
            print(f"- Councils: {result['councils']}")
            print(f"- Users: {result['users']}")
            print(f"- Grant Programs: {result['grants']}")
            print(f"- Applications: {result['applications']}")
        
        print("\nDatabase seeding completed!")
        print("\nDemo login credentials:")
        print("Council Admin: sarah.johnson@melbourne.vic.gov.au / demo123")
        print("Council Staff: michael.chen@melbourne.vic.gov.au / demo123")
        print("Community Member: emma.thompson@communityarts.org.au / demo123")
        print("Professional Consultant: david.wilson@grantsuccess.com.au / demo123")

