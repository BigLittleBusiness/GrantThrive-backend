# /home/ubuntu/grantthrive-platform/backend/src/routes/integrations_routes.py

from flask import Blueprint, request, jsonify
from datetime import datetime
from ..integrations.hubspot_api import HubSpotConnector
from ..integrations.salesforce_api import SalesforceConnector
from ..integrations.quickbooks_api import QuickBooksConnector
from ..integrations.myob_api import MYOBConnector
from ..integrations.xero_api import XeroConnector
from ..integrations.technologyone_api import TechnologyOneConnector
from ..integrations.abn_api import ABRConnector
from ..integrations.nzbn_api import NZBNConnector
from ..integrations.docusign_api import DocuSignConnector
from ..integrations.sms_api import SMSConnector
from ..integrations.analytics_api import AnalyticsConnector

integrations_bp = Blueprint('integrations_bp', __name__)

# ABN/ABR Integration Endpoints
@integrations_bp.route('/integrations/abr/validate', methods=['POST'])
def validate_abn():
    """
    API endpoint to validate Australian Business Number (ABN).
    """
    data = request.get_json()
    abn = data.get('abn')

    if not abn:
        return jsonify({"status": "error", "message": "ABN is required."}), 400

    abr = ABRConnector()
    success, result = abr.validate_abn(abn)

    if success:
        return jsonify({"status": "success", "formatted_abn": result}), 200
    else:
        return jsonify({"status": "error", "message": result}), 400

@integrations_bp.route('/integrations/abr/lookup', methods=['POST'])
def lookup_abn_details():
    """
    API endpoint to lookup business details from ABR.
    """
    data = request.get_json()
    abn = data.get('abn')

    if not abn:
        return jsonify({"status": "error", "message": "ABN is required."}), 400

    abr = ABRConnector()
    success, business_data = abr.lookup_abn_details(abn)

    if success:
        return jsonify({"status": "success", "data": business_data}), 200
    else:
        return jsonify({"status": "error", "message": business_data}), 400

@integrations_bp.route('/integrations/abr/verify-eligibility', methods=['POST'])
def verify_grant_eligibility():
    """
    API endpoint to verify grant eligibility based on ABN.
    """
    data = request.get_json()
    abn = data.get('abn')

    if not abn:
        return jsonify({"status": "error", "message": "ABN is required."}), 400

    abr = ABRConnector()
    success, eligibility_data = abr.verify_grant_eligibility(abn)

    if success:
        return jsonify({"status": "success", "data": eligibility_data}), 200
    else:
        return jsonify({"status": "error", "message": eligibility_data}), 400

# NZBN Integration Endpoints
@integrations_bp.route('/integrations/nzbn/validate', methods=['POST'])
def validate_nzbn():
    """
    API endpoint to validate New Zealand Business Number (NZBN).
    """
    data = request.get_json()
    nzbn = data.get('nzbn')

    if not nzbn:
        return jsonify({"status": "error", "message": "NZBN is required."}), 400

    nzbn_connector = NZBNConnector()
    success, result = nzbn_connector.validate_nzbn(nzbn)

    if success:
        return jsonify({"status": "success", "formatted_nzbn": result}), 200
    else:
        return jsonify({"status": "error", "message": result}), 400

@integrations_bp.route('/integrations/nzbn/lookup', methods=['POST'])
def lookup_nzbn_details():
    """
    API endpoint to lookup business details from NZBN register.
    """
    data = request.get_json()
    nzbn = data.get('nzbn')

    if not nzbn:
        return jsonify({"status": "error", "message": "NZBN is required."}), 400

    nzbn_connector = NZBNConnector()
    success, business_data = nzbn_connector.lookup_nzbn_details(nzbn)

    if success:
        return jsonify({"status": "success", "data": business_data}), 200
    else:
        return jsonify({"status": "error", "message": business_data}), 400

# DocuSign Integration Endpoints
@integrations_bp.route('/integrations/docusign/create-agreement', methods=['POST'])
def create_grant_agreement():
    """
    API endpoint to create grant agreement for digital signing.
    """
    data = request.get_json()

    if not data.get('grant_data') or not data.get('council_signer') or not data.get('recipient_signer'):
        return jsonify({"status": "error", "message": "Grant data and signer information required."}), 400

    docusign = DocuSignConnector()
    success, envelope_id = docusign.create_grant_agreement(
        data['grant_data'],
        data['council_signer'],
        data['recipient_signer']
    )

    if success:
        return jsonify({"status": "success", "envelope_id": envelope_id}), 200
    else:
        return jsonify({"status": "error", "message": envelope_id}), 500

@integrations_bp.route('/integrations/docusign/status/<envelope_id>', methods=['GET'])
def get_envelope_status(envelope_id):
    """
    API endpoint to get DocuSign envelope status.
    """
    docusign = DocuSignConnector()
    success, status_data = docusign.get_envelope_status(envelope_id)

    if success:
        return jsonify({"status": "success", "data": status_data}), 200
    else:
        return jsonify({"status": "error", "message": status_data}), 500

# SMS Integration Endpoints
@integrations_bp.route('/integrations/sms/send', methods=['POST'])
def send_sms():
    """
    API endpoint to send SMS notification.
    """
    data = request.get_json()

    if not data.get('to_number') or not data.get('message'):
        return jsonify({"status": "error", "message": "Phone number and message are required."}), 400

    sms = SMSConnector(provider=data.get('provider', 'twilio'))
    success, message_id = sms.send_sms(
        data['to_number'],
        data['message'],
        data.get('message_type', 'notification')
    )

    if success:
        return jsonify({"status": "success", "message_id": message_id}), 200
    else:
        return jsonify({"status": "error", "message": message_id}), 500

@integrations_bp.route('/integrations/sms/send-grant-notification', methods=['POST'])
def send_grant_notification():
    """
    API endpoint to send grant-specific SMS notification.
    """
    data = request.get_json()

    if not data.get('to_number') or not data.get('grant_data') or not data.get('notification_type'):
        return jsonify({"status": "error", "message": "Phone number, grant data, and notification type are required."}), 400

    sms = SMSConnector(provider=data.get('provider', 'twilio'))
    success, message_id = sms.send_grant_notification(
        data['to_number'],
        data['grant_data'],
        data['notification_type']
    )

    if success:
        return jsonify({"status": "success", "message_id": message_id}), 200
    else:
        return jsonify({"status": "error", "message": message_id}), 500

# Analytics Integration Endpoints
@integrations_bp.route('/integrations/analytics/track-event', methods=['POST'])
def track_analytics_event():
    """
    API endpoint to track custom analytics event.
    """
    data = request.get_json()

    if not data.get('event_name') or not data.get('event_data'):
        return jsonify({"status": "error", "message": "Event name and data are required."}), 400

    analytics = AnalyticsConnector(provider=data.get('provider', 'google_analytics'))
    success, tracking_id = analytics.track_event(
        data['event_name'],
        data['event_data'],
        data.get('user_id')
    )

    if success:
        return jsonify({"status": "success", "tracking_id": tracking_id}), 200
    else:
        return jsonify({"status": "error", "message": tracking_id}), 500

@integrations_bp.route('/integrations/analytics/grant-analytics', methods=['GET'])
def get_grant_analytics():
    """
    API endpoint to get grant program analytics.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    council_id = request.args.get('council_id')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Start date and end date are required."}), 400

    analytics = AnalyticsConnector()
    success, analytics_data = analytics.get_grant_analytics(start_date, end_date, council_id)

    if success:
        return jsonify({"status": "success", "data": analytics_data}), 200
    else:
        return jsonify({"status": "error", "message": analytics_data}), 500

@integrations_bp.route('/integrations/analytics/user-analytics', methods=['GET'])
def get_user_analytics():
    """
    API endpoint to get user engagement analytics.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user_type = request.args.get('user_type')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Start date and end date are required."}), 400

    analytics = AnalyticsConnector()
    success, analytics_data = analytics.get_user_analytics(start_date, end_date, user_type)

    if success:
        return jsonify({"status": "success", "data": analytics_data}), 200
    else:
        return jsonify({"status": "error", "message": analytics_data}), 500

# HubSpot Integration Endpoints
@integrations_bp.route('/integrations/hubspot/sync', methods=['POST'])
def sync_hubspot_contact():
    """
    API endpoint to sync a contact with HubSpot.
    Expects JSON payload with contact details.
    """
    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({"status": "error", "message": "Missing contact data or email."}), 400

    hubspot = HubSpotConnector()
    success, message = hubspot.sync_contact(data)

    if success:
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 500

# Salesforce Integration Endpoints
@integrations_bp.route('/integrations/salesforce/sync-opportunity', methods=['POST'])
def sync_salesforce_opportunity():
    """
    API endpoint to sync grant application as Salesforce opportunity.
    """
    data = request.get_json()

    if not data or 'grant_title' not in data:
        return jsonify({"status": "error", "message": "Missing grant data."}), 400

    salesforce = SalesforceConnector()
    success, message = salesforce.sync_opportunity(data)

    if success:
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 500

@integrations_bp.route('/integrations/salesforce/sync-contact', methods=['POST'])
def sync_salesforce_contact():
    """
    API endpoint to sync contact with Salesforce.
    """
    data = request.get_json()

    if not data or 'email' not in data:
        return jsonify({"status": "error", "message": "Missing contact data."}), 400

    salesforce = SalesforceConnector()
    success, message = salesforce.sync_contact(data)

    if success:
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 500

# QuickBooks Integration Endpoints
@integrations_bp.route('/integrations/quickbooks/sync-budget', methods=['POST'])
def sync_quickbooks_budget():
    """
    API endpoint to sync grant budget with QuickBooks.
    """
    data = request.get_json()

    if not data or 'funding_amount' not in data:
        return jsonify({"status": "error", "message": "Missing grant budget data."}), 400

    quickbooks = QuickBooksConnector()
    success, message = quickbooks.sync_grant_budget(data)

    if success:
        return jsonify({"status": "success", "message": message}), 200
    else:
        return jsonify({"status": "error", "message": message}), 500

@integrations_bp.route('/integrations/quickbooks/financial-report', methods=['GET'])
def get_quickbooks_report():
    """
    API endpoint to generate QuickBooks financial report.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Missing date parameters."}), 400

    quickbooks = QuickBooksConnector()
    success, report_data = quickbooks.get_financial_report(start_date, end_date)

    if success:
        return jsonify({"status": "success", "data": report_data}), 200
    else:
        return jsonify({"status": "error", "message": report_data}), 500

# MYOB Integration Endpoints
@integrations_bp.route('/integrations/myob/sync-financials', methods=['POST'])
def sync_myob_financials():
    """
    API endpoint to sync grant financials with MYOB.
    """
    data = request.get_json()

    if not data or 'funding_amount' not in data:
        return jsonify({"status": "error", "message": "Missing grant financial data."}), 400

    myob = MYOBConnector()
    success, sync_summary = myob.sync_grant_financials(data)

    if success:
        return jsonify({"status": "success", "data": sync_summary}), 200
    else:
        return jsonify({"status": "error", "message": sync_summary}), 500

@integrations_bp.route('/integrations/myob/grant-report', methods=['GET'])
def get_myob_grant_report():
    """
    API endpoint to generate MYOB grant report.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Missing date parameters."}), 400

    myob = MYOBConnector()
    success, report_data = myob.generate_grant_report(start_date, end_date)

    if success:
        return jsonify({"status": "success", "data": report_data}), 200
    else:
        return jsonify({"status": "error", "message": report_data}), 500

# Xero Integration Endpoints
@integrations_bp.route('/integrations/xero/sync-grant', methods=['POST'])
def sync_xero_grant():
    """
    API endpoint to sync complete grant with Xero.
    """
    data = request.get_json()

    if not data or 'funding_amount' not in data:
        return jsonify({"status": "error", "message": "Missing grant data."}), 400

    xero = XeroConnector()
    success, sync_summary = xero.sync_complete_grant(data)

    if success:
        return jsonify({"status": "success", "data": sync_summary}), 200
    else:
        return jsonify({"status": "error", "message": sync_summary}), 500

@integrations_bp.route('/integrations/xero/financial-report', methods=['GET'])
def get_xero_financial_report():
    """
    API endpoint to generate Xero financial report.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Missing date parameters."}), 400

    xero = XeroConnector()
    success, report_data = xero.generate_financial_report(start_date, end_date)

    if success:
        return jsonify({"status": "success", "data": report_data}), 200
    else:
        return jsonify({"status": "error", "message": report_data}), 500

# TechnologyOne Integration Endpoints
@integrations_bp.route('/integrations/technologyone/sync-lifecycle', methods=['POST'])
def sync_technologyone_lifecycle():
    """
    API endpoint to sync complete grant lifecycle with TechnologyOne.
    """
    data = request.get_json()

    if not data or 'grant_id' not in data:
        return jsonify({"status": "error", "message": "Missing grant lifecycle data."}), 400

    t1 = TechnologyOneConnector()
    success, sync_summary = t1.sync_complete_grant_lifecycle(data)

    if success:
        return jsonify({"status": "success", "data": sync_summary}), 200
    else:
        return jsonify({"status": "error", "message": sync_summary}), 500

@integrations_bp.route('/integrations/technologyone/compliance-report', methods=['GET'])
def get_technologyone_compliance_report():
    """
    API endpoint to generate TechnologyOne compliance report.
    """
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if not start_date or not end_date:
        return jsonify({"status": "error", "message": "Missing date parameters."}), 400

    t1 = TechnologyOneConnector()
    success, report_data = t1.generate_compliance_report(start_date, end_date)

    if success:
        return jsonify({"status": "success", "data": report_data}), 200
    else:
        return jsonify({"status": "error", "message": report_data}), 500

# General Integration Status Endpoint
@integrations_bp.route('/integrations/status', methods=['GET'])
def get_integrations_status():
    """
    API endpoint to check status of all integrations.
    """
    status_results = {}
    
    # Test each integration
    integrations = [
        ('hubspot', HubSpotConnector),
        ('salesforce', SalesforceConnector),
        ('quickbooks', QuickBooksConnector),
        ('myob', MYOBConnector),
        ('xero', XeroConnector),
        ('technologyone', TechnologyOneConnector),
        ('abr', ABRConnector),
        ('nzbn', NZBNConnector),
        ('docusign', DocuSignConnector),
        ('sms', lambda: SMSConnector('twilio')),
        ('analytics', AnalyticsConnector)
    ]
    
    for name, connector_class in integrations:
        try:
            connector = connector_class()
            # Test authentication
            auth_success, auth_message = connector.authenticate()
            status_results[name] = {
                'status': 'connected' if auth_success else 'disconnected',
                'message': auth_message,
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            status_results[name] = {
                'status': 'error',
                'message': str(e),
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    return jsonify({"status": "success", "integrations": status_results}), 200

