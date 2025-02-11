from flask import Flask, redirect, url_for, session, request, render_template
import requests
import os
from config import Config  # Import the configuration file

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

# GitHub OAuth endpoints
GITHUB_AUTHORIZATION_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_USER_API_URL = 'https://api.github.com/user'

# Google OAuth endpoints
GOOGLE_AUTHORIZATION_URL = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USER_INFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo'

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login/github')
def login_github():
    return redirect(f'{GITHUB_AUTHORIZATION_URL}?client_id={Config.GITHUB_CLIENT_ID}&redirect_uri={Config.GITHUB_REDIRECT_URI}&scope=user')

@app.route('/login/github/callback')
def github_callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization code not found', 400

    data = {
        'client_id': Config.GITHUB_CLIENT_ID,
        'client_secret': Config.GITHUB_CLIENT_SECRET,
        'code': code,
        'redirect_uri': Config.GITHUB_REDIRECT_URI
    }
    headers = {'Accept': 'application/json'}
    response = requests.post(GITHUB_TOKEN_URL, data=data, headers=headers)

    if response.status_code != 200:
        return 'Failed to obtain access token', 400

    access_token = response.json().get('access_token')
    if not access_token:
        return 'Access token not found', 400

    headers = {'Authorization': f'token {access_token}'}
    user_response = requests.get(GITHUB_USER_API_URL, headers=headers)

    if user_response.status_code != 200:
        return 'Failed to fetch user information', 400

    user_info = user_response.json()
    session['user'] = {
        'name': user_info.get('name', user_info.get('login')),  
        'email': user_info.get('email', 'Not provided')  
    }
    return redirect(url_for('profile'))

@app.route('/login/google')
def login_google():
    return redirect(
        f'{GOOGLE_AUTHORIZATION_URL}?client_id={Config.GOOGLE_CLIENT_ID}'
        f'&redirect_uri={Config.GOOGLE_REDIRECT_URI}'
        f'&response_type=code&scope=email profile'
        f'&prompt=select_account'  # Force account selection
    )

@app.route('/login/google/callback')
def google_callback():
    code = request.args.get('code')
    if not code:
        return 'Authorization code not found', 400

    data = {
        'client_id': Config.GOOGLE_CLIENT_ID,
        'client_secret': Config.GOOGLE_CLIENT_SECRET,
        'code': code,
        'redirect_uri': Config.GOOGLE_REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    response = requests.post(GOOGLE_TOKEN_URL, data=data)

    if response.status_code != 200:
        return 'Failed to obtain access token', 400

    access_token = response.json().get('access_token')
    if not access_token:
        return 'Access token not found', 400

    headers = {'Authorization': f'Bearer {access_token}'}
    user_response = requests.get(GOOGLE_USER_INFO_URL, headers=headers)

    if user_response.status_code != 200:
        return 'Failed to fetch user information', 400

    user_info = user_response.json()
    session['user'] = {
        'name': user_info.get('name', 'Not provided'),
        'email': user_info.get('email', 'Not provided')
    }
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    user_info = session.get('user')
    if not user_info:
        return redirect(url_for('index'))
    return render_template('profile.html', user=user_info)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)