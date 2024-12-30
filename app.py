import identity.web
import requests
import json
from flask import Flask, redirect, render_template, request, session, url_for, send_file, jsonify
from flask_session import Session
import os
from datetime import datetime

import app_config
from token_script import save_token  # Import the save_token function

__version__ = "0.8.0"  # The version of this sample, for troubleshooting purpose

app = Flask(__name__)
app.config.from_object(app_config)
assert app.config["REDIRECT_PATH"] != "/", "REDIRECT_PATH must not be /"
Session(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/2.2.x/deploying/proxy_fix/
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.jinja_env.globals.update(Auth=identity.web.Auth)  # Useful in template for B2C
auth = identity.web.Auth(
    session=session,
    authority=app.config["AUTHORITY"],
    client_id=app.config["CLIENT_ID"],
    client_credential=app.config["CLIENT_SECRET"],
)

@app.route("/get_client_token")
def get_client_token():
    """Endpoint to get a new token using client credentials"""
    token = auth.get_token_for_client(app_config.SCOPE)
    if "access_token" in token:
        save_token(token["access_token"])
        return jsonify({"status": "success", "message": "Token saved successfully"})
    return jsonify({"status": "error", "message": "Could not get token"}), 400

@app.route("/login")
def login():
    return render_template("login.html", version=__version__, **auth.log_in(
        scopes=app_config.SCOPE, # Have user consent to scopes during log-in
        redirect_uri=url_for("auth_response", _external=True), # Optional. If present, this absolute URL must match your app's redirect_uri registered in Azure Portal
        prompt="select_account",  # Optional. More values defined in  https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        ))

@app.route(app_config.REDIRECT_PATH)
def auth_response():
    result = auth.complete_log_in(request.args)
    if "error" in result:
        return render_template("auth_error.html", result=result)
    
    # Get and save token after successful login
    token = auth.get_token_for_user(app_config.SCOPE)
    if "access_token" in token:
        save_token(token["access_token"])
        print("Token saved successfully!")
    
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    return redirect(auth.log_out(url_for("index", _external=True)))

@app.route("/")
def index():
    if not (app.config["CLIENT_ID"] and app.config["CLIENT_SECRET"]):
        # This check is not strictly necessary.
        # You can remove this check from your production code.
        return render_template('config_error.html')
    if not auth.get_user():
        return redirect(url_for("login"))
    return render_template('index.html', user=auth.get_user(), version=__version__)

@app.route("/call_downstream_api")
def call_downstream_api():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    # Use access token to call downstream api
    api_result = requests.get(
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']},
        timeout=30,
    ).json()
    return render_template('display.html', result=api_result)

@app.route("/get_all_users")
def get_all_users():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        if token.get("error") == "invalid_grant" or token.get("error_description", "").startswith("AADSTS65001"):
            return render_template("auth_error.html", 
                result={
                    "error": "Admin Consent Required",
                    "error_description": "This operation requires admin consent. Please have an administrator grant permissions to this application."
                })
        return redirect(url_for("login"))
    
    try:
        # First, check if current user is admin by checking directory roles
        current_user_roles = requests.get(
            "https://graph.microsoft.com/v1.0/me/memberOf",
            headers={'Authorization': 'Bearer ' + token['access_token']},
            timeout=30,
        ).json()
        
        is_admin = False
        admin_roles = ["Global Administrator", "Directory Readers", "Global Reader"]
        
        if 'value' in current_user_roles:
            for role in current_user_roles['value']:
                if role.get('displayName') in admin_roles:
                    is_admin = True
                    break
        
        # Get all users with their roles
        users_response = requests.get(
            "https://graph.microsoft.com/v1.0/users?$select=displayName,mail,userPrincipalName,id,accountEnabled",
            headers={'Authorization': 'Bearer ' + token['access_token']},
            timeout=30,
        )
        
        if users_response.status_code == 403:
            return render_template("auth_error.html", 
                result={
                    "error": "Insufficient Permissions",
                    "error_description": "You don't have the required permissions to view all users. This operation requires admin privileges."
                })
        
        users_data = users_response.json()
        
        # For each user, get their directory roles
        if is_admin and 'value' in users_data:
            for user in users_data['value']:
                try:
                    roles_response = requests.get(
                        f"https://graph.microsoft.com/v1.0/users/{user['id']}/memberOf",
                        headers={'Authorization': 'Bearer ' + token['access_token']},
                        timeout=30,
                    ).json()
                    
                    user['roles'] = []
                    if 'value' in roles_response:
                        user['roles'] = [role['displayName'] for role in roles_response['value']
                                       if '@odata.type' in role and '#microsoft.graph.directoryRole' in role['@odata.type']]
                except:
                    user['roles'] = []
        
        # Store the users data in session for export
        session['users_data'] = users_data
        
        return render_template('all_users.html', result=users_data, is_admin=is_admin)
        
    except requests.exceptions.RequestException as e:
        return render_template("auth_error.html", 
            result={
                "error": "API Error",
                "error_description": str(e)
            })

@app.route("/export_users")
def export_users():
    if 'users_data' not in session:
        return redirect(url_for("get_all_users"))
    
    # Create exports directory if it doesn't exist
    if not os.path.exists('Data'):
        os.makedirs('Data')
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f'Data/users_data_{timestamp}.json'
    
    # Write the data to a JSON file
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(session['users_data'], f, indent=4, ensure_ascii=False)
    
    # Send the file to the user
    return send_file(
        filename,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'users_export_{timestamp}.json'
    )

@app.route("/export_emails")
def export_emails():
    token = auth.get_token_for_user(app_config.SCOPE)
    if "error" in token:
        return redirect(url_for("login"))
    
    try:
        # Get emails from inbox
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me/messages?$select=subject,receivedDateTime,from,toRecipients,bodyPreview&$top=50&$orderby=receivedDateTime desc",
            headers={'Authorization': 'Bearer ' + token['access_token']},
            timeout=30,
        )
        
        if response.status_code == 403:
            return render_template("auth_error.html", 
                result={
                    "error": "Insufficient Permissions",
                    "error_description": "You don't have the required permissions to access emails."
                })
        
        emails_data = response.json()
        
        # Create Data directory if it doesn't exist
        if not os.path.exists('Data'):
            os.makedirs('Data')
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f'Data/emails_{timestamp}.json'
        
        # Process emails to make them more readable
        processed_emails = {
            "emails": [
                {
                    "subject": email.get("subject", "No Subject"),
                    "received": email.get("receivedDateTime", ""),
                    "from": email.get("from", {}).get("emailAddress", {}).get("address", "Unknown"),
                    "to": [recipient.get("emailAddress", {}).get("address", "Unknown") 
                          for recipient in email.get("toRecipients", [])],
                    "preview": email.get("bodyPreview", "")
                }
                for email in emails_data.get("value", [])
            ],
            "exported_at": datetime.now().isoformat(),
            "total_emails": len(emails_data.get("value", []))
        }
        
        # Write the data to a JSON file
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(processed_emails, f, indent=4, ensure_ascii=False)
        
        # Send the file to the user
        return send_file(
            filename,
            mimetype='application/json',
            as_attachment=True,
            download_name=f'emails_export_{timestamp}.json'
        )
        
    except requests.exceptions.RequestException as e:
        return render_template("auth_error.html", 
            result={
                "error": "API Error",
                "error_description": str(e)
            })

if __name__ == "__main__":
    app.run()
