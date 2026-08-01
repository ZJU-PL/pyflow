from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound
import os
import html

class UserDB:
    def __init__(self):
        self.users = {
            'admin': 'password123',
            'user1': 'mypassword'
        }
    
    def validate_user(self, username, password):
        return self.users.get(username) == password

db = UserDB()

@view_config(route_name='home', renderer='templates/home.pt')
def home_view(request):
    return {}

@view_config(route_name='login', renderer='templates/login.pt')
def login_view(request):
    if request.method == 'POST':
        username = request.params.get('username', '')
        password = request.params.get('password', '')
        
        if db.validate_user(username, password):
            headers = remember(request, username)
            return HTTPFound(location=request.route_url('dashboard'), headers=headers)
        
        # Vulnerable function - reflects user input without proper escaping
        error_msg = f"Invalid credentials for user '{username}'"
        return {'error': error_msg}
    
    return {}

@view_config(route_name='dashboard', renderer='templates/dashboard.pt')
def dashboard_view(request):
    if not authenticated_userid(request):
        return HTTPFound(location=request.route_url('login'))
    return {'username': authenticated_userid(request)}

@view_config(route_name='logout')
def logout_view(request):
    headers = forget(request)
    return HTTPFound(location=request.route_url('home'), headers=headers)

def main(global_config, **settings):
    config = Configurator(settings=settings)
    
    # Set up authentication
    from pyramid.authentication import AuthTktAuthenticationPolicy
    from pyramid.authorization import ACLAuthorizationPolicy
    authn_policy = AuthTktAuthenticationPolicy('s3cr3t', hashalg='sha512')
    authz_policy = ACLAuthorizationPolicy()
    config.set_authentication_policy(authn_policy)
    config.set_authorization_policy(authz_policy)
    
    # Create template directory
    if not os.path.exists('templates'):
        os.makedirs('templates')
    
    # Create templates
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
<head><title>Login</title></head>
<body>
    <h1>Login</h1>
    % if error:
        <div style="color: red">${error}</div>  <!-- XSS vulnerability here -->
    % endif
    <form method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>''')
    
    with open('templates/dashboard.pt', 'w') as f:
        f.write('''<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
    <h1>Welcome ${username}</h1>
    <a href="${request.route_url('logout')}">Logout</a>
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