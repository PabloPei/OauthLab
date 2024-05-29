import os
import requests
from urllib.parse import urlparse, parse_qs
from flask import Flask, request, Flask, redirect, url_for, session, render_template
#from api.route.user_route import user_bp
from api.errors.errors import *
from dotenv import load_dotenv
from requests_oauthlib import OAuth2Session


### App
app = Flask(__name__)

### Environment variables
load_dotenv()

### Blueprints 
#app.register_blueprint(user_bp) 
 
### Errors
app.register_error_handler(400, handle_bad_request_error)
app.register_error_handler(401, handle_unauthorized_error) 
app.register_error_handler(403, handle_forbidden_error)
app.register_error_handler(404, handle_not_found_error)
app.register_error_handler(409, handle_conflict_error)
app.register_error_handler(500, handle_generic_error)

### Conf
app.config['SECRET_KEY'] = open(os.environ.get('SECRET_KEY_PATH')).read()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = os.environ.get('INSECURE_TRANSPORT') 

### App

@app.route('/')
def home():
    return render_template('index.html', auth_oauth_code_flow_input = url_for('auth_oauth_code_flow_input'))

@app.route('/auth/oauth_code_flow/input')
def auth_oauth_code_flow_input():
    session['type'] = request.args.get('flow')
    return render_template('oauth_code_flow_input.html', auth_oauth_code_flow = url_for('auth_oauth_code_flow'))

@app.route('/auth/oauth_code_flow', methods=['POST'])
def auth_oauth_code_flow(): 
    
    session['redirect_uri'] = request.form['redirect_uri']
    session['client_id'] = request.form['client_id']
    session['scope'] = request.form['scope']
    session['authorization_uri'] = request.form['authorization_uri']
    session['token_uri'] = request.form['token_uri']


    oauth = OAuth2Session(session.get('client_id'), redirect_uri=session.get('redirect_uri'), scope=session.get('scope'))
    authorization_url, state = oauth.authorization_url(session.get('authorization_uri'), access_type='offline', prompt='select_account')
    session['oauth_state'] = state
    url = urlparse(authorization_url)
    url_query = parse_qs(url.query)
    return render_template ('oauth_code_flow_request.html', authorization_url = authorization_url, token_uri= session.get('token_uri'), url =url.netloc + url.path ,response_type = url_query['response_type'], scope = url_query['scope'], redirect_uri = url_query['redirect_uri'], oauth_state = state)
    

@app.route('/auth/oauth/callback')
def auth_oauth_callback():

    state = request.args.get('state')
    session['returned_state'] = state
    code = request.args.get('code')
    session['authorization_code'] = code
    scope = request.args.get('scope')
    if state == session['oauth_state']:
        message = "The callback state is identical to the one sent in the request! You can continue with OAuth Code Flow."
    else:
        message = "The callback state is different from the one sent in the request! You cannot continue with the OAuth Code Flow."

    return render_template('oauth_code_flow_code.html', code=code, scope=scope, return_state=state, original_state=session['oauth_state'], message=message, user_info_url=url_for('exchange_code_for_token_request'))
   
@app.route('/auth/oauth/exchange_code_for_token_request')
def exchange_code_for_token_request():
    return render_template('oauth_code_flow_code_for_token_input.html')

@app.route('/auth/oauth/exchange_code_for_token', methods=['POST'])
def exchange_code_for_token():
    secret_id = request.form['secret_id']
    authorization_code = session.get('authorization_code')
    
    oauth = OAuth2Session(
        client_id=session.get('client_id'),
        redirect_uri=session.get('redirect_uri')
    )
    
    authorization_response = request.url.replace('/auth/oauth/exchange_code_for_token', f'/auth/oauth/callback?code={authorization_code}&state={session["oauth_state"]}')
    
    token = oauth.fetch_token(
        session.get('token_uri'),
        client_secret=secret_id,
        authorization_response=authorization_response
    )
    
    session['oauth_token'] = token

    if (session['type'] == "code_flow"):
        return render_template('oauth_code_flow_token.html', token=token['access_token'], user_info_url = url_for('get_user_info_request'))
    else:
        return render_template('oauth_openid_flow_token.html', openid_token = token['id_token'],  home=url_for('home'))

@app.route('/get_user_info_request')
def get_user_info_request():
        return render_template ('oauth_code_flow_token_input.html')

@app.route('/get_user_info', methods=['POST'])
def auth_oauth_user_info():
    
    token = request.form['access_token']
    url = request.form['user_info_uri']

    headers = {
        'Authorization': f'Bearer {token}'
    }
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        user_data = response.json()
    else:
        print(response)

    return render_template ('oauth_user_info.html', user_name = user_data['name'], avatar=user_data['picture'], user_email = user_data.get('email', ''), home=url_for('home'))
        
if __name__ == '__main__':

    app.run(host='0.0.0.0', debug=True)
