from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound
import os
import html
import secrets
import hashlib

class UserDB:
    def __init__(self):
        # Store password hashes instead of plain text
        self.users = {
            'admin': self._hash_password('password123'),
            'user1': self._hash_password('mypassword')
        }
    
    def _hash_password(self, password):
        """Hash password with salt using PBKDF2-HMAC-SHA256"""
        salt = secrets.token_hex(16)
        return f"{salt}:{hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()}"
    
    def validate_user(self, username, password):
        stored = self.users.get(username)
        if not stored:
            return False
        salt, hashed = stored.split(':')
        new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
        return hashed == new_hash

db = UserDB()

@view_config(route_name='home', renderer='templates/home.pt')
def home_view(request):
    return {}

@view_config(route_name='login', renderer='templates/login.pt')
def login_view(request):
    if request.method == 'POST':
        username = request.params.get('username', '')
        password = request.params.get('password', '')
        
        # Basic input validation
        if not username or not password:
            return {'error': 'Username and password are required'}
        
        if db.validate_user(username, password):
            headers = remember(request, username)
            return HTTPFound(location=request.route_url('dashboard'), headers=headers)
        
        # Escape user input before displaying
        error_msg = f"Invalid credentials for user '{html.escape(username)}'"
        return {'error': error_msg}
    
    return {}

@view_config(route_name='dashboard', renderer='templates/dashboard.pt')
def dashboard_view(request):
    if not authenticated_userid(request):
        return HTTPFound(location=request.route_url('login'))
    return {'username': html.escape(authenticated_userid(request))}

@view_config(route_name='logout')
def logout_view(request):
    headers = forget(request)
    return HTTPFound(location=request.route_url('home'), headers=headers)

def main(global_config, **settings):
    config = Configurator(settings=settings)
    
    # Set up authentication with secure secret
    from pyramid.authentication import AuthTktAuthenticationPolicy
    from pyramid.authorization import ACLAuthorizationPolicy
    authn_policy = AuthTktAuthenticationPolicy(
        secrets.token_urlsafe(64),  # Generate strong random secret
        hashalg='sha512',
        secure=True,  # Only send cookie over HTTPS
        httponly=True,  # Prevent client-side JS access
        samesite='Lax'  # CSRF protection
    )
    authz_policy = ACLAuthorizationPolicy()
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    
    # Add CSRF protection
    config.set_default_csrf_options(require_csrf=True)
    
    # Create template directory
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Create templates with proper escaping
    with open('templates/home.pt', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head><title>Home</title></head>
<body>
    <h1>Welcome</h1>
    <a href="${request.route_url('login')}">Login</a>
</body>
</html>''')
    
    with open('templates/login.pt', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>Login</h1>
    % if error:
        <div style="color: red">${error | h}</div>  <!-- Fixed: Added h filter for escaping -->
    % endif
    <form method="post">
        <input type="hidden" name="csrf_token" value="${request.session.get_csrf_token()}">
        Username: <input type="text" name="username" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>''')
    
    with open('templates/dashboard.pt', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>Welcome ${username | h}</h1>  <!-- Added h filter for escaping -->
    <form action="${request.route_url('logout')}" method="post">
        <input type="hidden" name="csrf_token" value="${request.session.get_csrf_token()}">
        <button type="submit">Logout</button>
    </form>
</body>
</html>''')
    
    # Set up routes
    config.add_route('home', '/')
    config.add_route('login', '/login')
    config.add_route('dashboard', '/dashboard')
    config.add_route('logout', '/logout')
    
    config.scan()
    return config.make_wsgi_app()

def remember(request, username):
    from pyramid.security import remember
    return remember(request, username)

def forget(request):
    from pyramid.security import forget
    return forget(request)

def authenticated_userid(request):
    from pyramid.security import authenticated_userid
    return authenticated_userid(request)

if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    app = main({})
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()