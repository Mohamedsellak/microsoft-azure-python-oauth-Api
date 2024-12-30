import json
import os
import requests
import app_config

TOKEN_FILE = 'saved_token.json'

def get_new_token():
    """Get a new token using client credentials flow"""
    # Extract tenant from authority URL
    tenant = app_config.AUTHORITY.split('/')[-1]
    token_url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': app_config.CLIENT_ID,
        'client_secret': app_config.CLIENT_SECRET,
        'scope': 'https://graph.microsoft.com/.default'
    }
    
    try:
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            if 'access_token' in token_data:
                save_token(token_data['access_token'])
                return token_data['access_token']
        print(f"Error getting token: {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"Exception while getting token: {e}")
    return None

def load_saved_token():
    """Load token from file"""
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            token_data = json.load(f)
            return token_data.get('access_token')
    return None

def save_token(access_token):
    """Save access token"""
    token_data = {
        'access_token': access_token
    }
    with open(TOKEN_FILE, 'w') as f:
        json.dump(token_data, f, indent=4)
    print("Token saved successfully!")

def get_users(access_token, retry=True):
    """Get users using the access token"""
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.get(
            "https://graph.microsoft.com/v1.0/users?$select=displayName,mail,userPrincipalName,id,accountEnabled",
            headers=headers,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 and retry:  # Token expired
            print("Token expired, getting new token...")
            new_token = get_new_token()
            if new_token:
                return get_users(new_token, retry=False)  # Try once with new token
            print("Could not get new token.")
        
        print(f"Error getting users: {response.status_code}")
        print(response.text)
    except Exception as e:
        print(f"Error making request: {e}")
    return None

def main():
    try:
        # Try to load saved token first
        access_token = load_saved_token()
        
        # If no token or token doesn't look valid, get a new one
        if not access_token or not access_token.startswith("eyJ"):
            print("Getting new token...")
            access_token = get_new_token()
            if not access_token:
                print("Failed to get token")
                return
        
        print("Getting users...")
        users_data = get_users(access_token)
        if users_data:
            # Save users to file
            output_file = 'Data/users_data.json'
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(users_data, f, indent=4, ensure_ascii=False)
            print(f"Users data saved to {output_file}")
        else:
            print("Failed to get users.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main() 