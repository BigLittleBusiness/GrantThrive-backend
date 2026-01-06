import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import os
from datetime import datetime
from jinja2 import Template

class EmailService:
    """Email service for sending notifications"""
    
    def __init__(self):
        # Email configuration (in production, use environment variables)
        self.smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        self.smtp_port = int(os.getenv('SMTP_PORT', '587'))
        self.smtp_username = os.getenv('SMTP_USERNAME', 'noreply@grantthrive.com')
        self.smtp_password = os.getenv('SMTP_PASSWORD', 'your-app-password')
        self.from_email = os.getenv('FROM_EMAIL', 'noreply@grantthrive.com')
        self.from_name = os.getenv('FROM_NAME', 'GrantThrive')
        
    def send_email(self, to_email, subject, html_content, text_content=None, attachments=None):
        """Send email with HTML content"""
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = f"{self.from_name} <{self.from_email}>"
            message['To'] = to_email
            
            # Add text content
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                message.attach(text_part)
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            # Add attachments
            if attachments:
                for attachment_path in attachments:
                    if os.path.exists(attachment_path):
                        with open(attachment_path, 'rb') as attachment:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(attachment.read())
                        
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {os.path.basename(attachment_path)}'
                        )
                        message.attach(part)
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.smtp_username, self.smtp_password)
                server.sendmail(self.from_email, to_email, message.as_string())
            
            return True
            
        except Exception as e:
            print(f"Email sending failed: {str(e)}")
            return False
    
    def send_welcome_email(self, user_email, user_name, user_role):
        """Send welcome email to new user"""
        subject = "Welcome to GrantThrive!"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #1e40af; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background-color: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Welcome to GrantThrive!</h1>
                </div>
                <div class="content">
                    <h2>Hello {{ user_name }},</h2>
                    <p>Welcome to GrantThrive, Australia's leading grant management platform!</p>
                    
                    {% if user_role == 'community_member' %}
                    <p>As a community member, you can now:</p>
                    <ul>
                        <li>Browse available grants from councils across Australia</li>
                        <li>Submit grant applications online</li>
                        <li>Track your application progress</li>
                        <li>Access resources and community support</li>
                    </ul>
                    {% elif user_role == 'council_staff' or user_role == 'council_admin' %}
                    <p>As council staff, you can now:</p>
                    <ul>
                        <li>Manage grant programs for your council</li>
                        <li>Review and process applications</li>
                        <li>Communicate with applicants</li>
                        <li>Generate reports and analytics</li>
                    </ul>
                    {% elif user_role == 'professional_consultant' %}
                    <p>As a professional consultant, you can now:</p>
                    <ul>
                        <li>Access the consultant marketplace</li>
                        <li>Connect with potential clients</li>
                        <li>Manage your consulting projects</li>
                        <li>Access professional resources</li>
                    </ul>
                    {% endif %}
                    
                    <p>Get started by logging into your account:</p>
                    <a href="https://grantthrive.com/login" class="button">Login to GrantThrive</a>
                    
                    <p>If you have any questions, our support team is here to help!</p>
                </div>
                <div class="footer">
                    <p>© 2024 GrantThrive. All rights reserved.</p>
                    <p>This email was sent to {{ user_email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            user_email=user_email,
            user_role=user_role
        )
        
        return self.send_email(user_email, subject, html_content)
    
    def send_application_confirmation(self, user_email, user_name, grant_title, application_id):
        """Send application confirmation email"""
        subject = f"Application Submitted: {grant_title}"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #059669; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background-color: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background-color: #059669; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                .highlight { background-color: #ecfdf5; padding: 15px; border-left: 4px solid #059669; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Application Submitted Successfully!</h1>
                </div>
                <div class="content">
                    <h2>Hello {{ user_name }},</h2>
                    <p>Your grant application has been successfully submitted!</p>
                    
                    <div class="highlight">
                        <strong>Grant:</strong> {{ grant_title }}<br>
                        <strong>Application ID:</strong> #{{ application_id }}<br>
                        <strong>Submitted:</strong> {{ current_date }}
                    </div>
                    
                    <h3>What happens next?</h3>
                    <ol>
                        <li>Your application will be reviewed by the grant committee</li>
                        <li>You'll receive updates via email as your application progresses</li>
                        <li>The review process typically takes 2-4 weeks</li>
                        <li>You'll be notified of the final decision</li>
                    </ol>
                    
                    <p>You can track your application progress anytime:</p>
                    <a href="https://grantthrive.com/applications/{{ application_id }}" class="button">View Application Status</a>
                    
                    <p>Thank you for using GrantThrive!</p>
                </div>
                <div class="footer">
                    <p>© 2024 GrantThrive. All rights reserved.</p>
                    <p>This email was sent to {{ user_email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            user_email=user_email,
            grant_title=grant_title,
            application_id=application_id,
            current_date=datetime.now().strftime("%B %d, %Y")
        )
        
        return self.send_email(user_email, subject, html_content)
    
    def send_application_status_update(self, user_email, user_name, grant_title, application_id, new_status, message=None):
        """Send application status update email"""
        status_messages = {
            'under_review': 'Your application is now under review',
            'requires_clarification': 'Additional information required',
            'approved': 'Congratulations! Your application has been approved',
            'rejected': 'Application decision notification'
        }
        
        subject = f"Application Update: {grant_title}"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: {% if new_status == 'approved' %}#059669{% elif new_status == 'rejected' %}#dc2626{% else %}#1e40af{% endif %}; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background-color: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background-color: #1e40af; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                .highlight { background-color: {% if new_status == 'approved' %}#ecfdf5{% elif new_status == 'rejected' %}#fef2f2{% else %}#eff6ff{% endif %}; padding: 15px; border-left: 4px solid {% if new_status == 'approved' %}#059669{% elif new_status == 'rejected' %}#dc2626{% else %}#1e40af{% endif %}; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Application Status Update</h1>
                </div>
                <div class="content">
                    <h2>Hello {{ user_name }},</h2>
                    <p>{{ status_message }}</p>
                    
                    <div class="highlight">
                        <strong>Grant:</strong> {{ grant_title }}<br>
                        <strong>Application ID:</strong> #{{ application_id }}<br>
                        <strong>New Status:</strong> {{ new_status|title }}<br>
                        <strong>Updated:</strong> {{ current_date }}
                    </div>
                    
                    {% if message %}
                    <h3>Additional Information:</h3>
                    <p>{{ message }}</p>
                    {% endif %}
                    
                    {% if new_status == 'approved' %}
                    <h3>Congratulations!</h3>
                    <p>Your grant application has been approved. You will receive further instructions about the next steps and funding disbursement.</p>
                    {% elif new_status == 'requires_clarification' %}
                    <h3>Action Required</h3>
                    <p>Please review the feedback and provide the requested information to continue the review process.</p>
                    {% elif new_status == 'rejected' %}
                    <h3>Next Steps</h3>
                    <p>While this application was not successful, we encourage you to review the feedback and consider applying for future grant opportunities.</p>
                    {% endif %}
                    
                    <p>View your application for more details:</p>
                    <a href="https://grantthrive.com/applications/{{ application_id }}" class="button">View Application</a>
                </div>
                <div class="footer">
                    <p>© 2024 GrantThrive. All rights reserved.</p>
                    <p>This email was sent to {{ user_email }}</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            user_email=user_email,
            grant_title=grant_title,
            application_id=application_id,
            new_status=new_status,
            status_message=status_messages.get(new_status, 'Your application status has been updated'),
            message=message,
            current_date=datetime.now().strftime("%B %d, %Y")
        )
        
        return self.send_email(user_email, subject, html_content)
    
    def send_admin_approval_notification(self, admin_email, user_name, user_email, user_role):
        """Send notification to admin about new user registration"""
        subject = f"New User Registration Requires Approval: {user_name}"
        
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background-color: #f59e0b; color: white; padding: 20px; text-align: center; }
                .content { padding: 20px; background-color: #f9f9f9; }
                .button { display: inline-block; padding: 12px 24px; background-color: #f59e0b; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
                .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                .highlight { background-color: #fffbeb; padding: 15px; border-left: 4px solid #f59e0b; margin: 15px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>New User Registration</h1>
                </div>
                <div class="content">
                    <h2>Admin Approval Required</h2>
                    <p>A new user has registered and requires approval:</p>
                    
                    <div class="highlight">
                        <strong>Name:</strong> {{ user_name }}<br>
                        <strong>Email:</strong> {{ user_email }}<br>
                        <strong>Role:</strong> {{ user_role|title }}<br>
                        <strong>Registration Date:</strong> {{ current_date }}
                    </div>
                    
                    <p>Please review and approve or reject this registration:</p>
                    <a href="https://grantthrive.com/admin/users/pending" class="button">Review Registration</a>
                </div>
                <div class="footer">
                    <p>© 2024 GrantThrive. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        html_content = template.render(
            user_name=user_name,
            user_email=user_email,
            user_role=user_role,
            current_date=datetime.now().strftime("%B %d, %Y")
        )
        
        return self.send_email(admin_email, subject, html_content)

# Global email service instance
email_service = EmailService()

