import os
import sys
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from flasgger import Swagger
from src.models.user import db
from src.routes.user import user_bp
from src.routes.auth import auth_bp
from src.routes.grants import grants_bp
from src.routes.applications import applications_bp
from src.routes.admin import admin_bp
from src.routes.files import files_bp
from src.routes.grant_wizard import grant_wizard_bp
from src.routes.application_review import application_review_bp
from src.routes.integrations_routes import integrations_bp
from src.routes.communication_routes import communication_bp
from src.routes.qr_code_routes import qr_code_bp
from src.routes.quick_wins_routes import quick_wins_bp
from src.routes.community_engagement_routes import community_engagement_bp
from src.routes.staff_invitation import staff_invitation_bp
from src.routes.community import community_bp
from src.routes.council import council_bp

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = 'asdf#FGSgvasgf$5$WGT'

# Enable CORS for all routes
CORS(app, origins="*", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])

# ── Swagger / Flasgger ──────────────────────────────────────────────────────
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "GrantThrive API",
        "description": (
            "REST API for the GrantThrive platform.  \n"
            "Authenticate via **POST /api/auth/login** to receive a JWT bearer token, "
            "then click **Authorize** and enter `Bearer <token>`."
        ),
        "version": "1.0.0",
        "contact": {
            "name": "GrantThrive Support",
            "email": "support@grantthrive.com.au",
        },
    },
    "basePath": "/",
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Enter your JWT token as: **Bearer &lt;token&gt;**",
        }
    },
    "security": [{"BearerAuth": []}],
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "tags": [
        {"name": "Auth",               "description": "Authentication — register, login, token verification"},
        {"name": "Admin",              "description": "System admin — user management and platform stats"},
        {"name": "Users",              "description": "User profile CRUD"},
        {"name": "Grants",             "description": "Grant program management"},
        {"name": "Applications",       "description": "Grant application lifecycle"},
        {"name": "Application Review", "description": "Staff review and scoring of applications"},
        {"name": "Grant Wizard",       "description": "Step-by-step grant creation wizard"},
        {"name": "Staff Invitation",   "description": "Council admin inviting and managing staff"},
        {"name": "Files",              "description": "File upload and retrieval"},
        {"name": "Analytics",          "description": "Platform analytics and reporting"},
        {"name": "Communication",      "description": "Notifications and messaging"},
        {"name": "Community Engagement","description": "Community voting, forums, and engagement"},
        {"name": "Integrations",       "description": "Third-party integrations (Xero, QuickBooks, etc.)"},
        {"name": "QR Codes",           "description": "QR code generation and management"},
        {"name": "Quick Wins",         "description": "Calendar links, push notifications, prefill, and progress tracking"},
        {"name": "Health",             "description": "API health check"},
        {"name": "Community",          "description": "Community member — profile, grants, applications, dashboard"},
        {"name": "Council",            "description": "Council staff/admin — grants, applications, staff management, dashboard"},
    ],
}

Swagger(app, config=swagger_config, template=swagger_template)
# ────────────────────────────────────────────────────────────────────────────

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(grants_bp, url_prefix='/api')
app.register_blueprint(applications_bp, url_prefix='/api')
app.register_blueprint(admin_bp, url_prefix='/api')
app.register_blueprint(files_bp, url_prefix='/api')
app.register_blueprint(grant_wizard_bp, url_prefix='/api')
app.register_blueprint(application_review_bp, url_prefix='/api')
app.register_blueprint(integrations_bp, url_prefix='/api')
app.register_blueprint(communication_bp, url_prefix='/api')
app.register_blueprint(qr_code_bp, url_prefix='/api')
app.register_blueprint(quick_wins_bp, url_prefix='/api')
app.register_blueprint(community_engagement_bp, url_prefix='/api')
app.register_blueprint(staff_invitation_bp, url_prefix='/api')
app.register_blueprint(community_bp, url_prefix='/api')
app.register_blueprint(council_bp, url_prefix='/api')

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'database', 'app.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
        return "Static folder not configured", 404
    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        index_path = os.path.join(static_folder_path, 'index.html')
        if os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "index.html not found", 404

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """
    API health check
    ---
    tags:
      - Health
    security: []
    responses:
      200:
        description: API is running
        schema:
          type: object
          properties:
            status:
              type: string
              example: healthy
            message:
              type: string
              example: GrantThrive API is running
    """
    return {'status': 'healthy', 'message': 'GrantThrive API is running'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
