from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from wsgiref.simple_server import make_server
import html
from pyramid.httpexceptions import HTTPBadRequest

class NotificationSystem:
    def __init__(self):
        self.notifications = []
    
    def add_notification(self, user_id, message):
        # Sanitize input before storing
        clean_user_id = html.escape(user_id)
        clean_message = html.escape(message)
        self.notifications.append({
            'user_id': clean_user_id,
            'message': clean_message,
            'read': False
        })
    
    def get_user_notifications(self, user_id):
        # Return sanitized copies of notifications
        clean_user_id = html.escape(user_id)
        return [{
            'user_id': n['user_id'],  # Already sanitized
            'message': n['message'],   # Already sanitized
            'read': n['read']
        } for n in self.notifications if n['user_id'] == clean_user_id]

notification_system = NotificationSystem()

@view_config(route_name='home', renderer='string')
def home_view(request):
    return "Welcome to the notification system. Visit /notifications/<user_id>"

@view_config(route_name='add_notification', request_method='POST')
def add_notification_view(request):
    user_id = request.POST.get('user_id')
    message = request.POST.get('message')
    
    if not user_id or not message:
        return HTTPBadRequest("Both user_id and message are required")
    
    notification_system.add_notification(user_id, message)
    return Response("Notification added")

@view_config(route_name='view_notifications', renderer='templates/notifications.pt')
def view_notifications_view(request):
    user_id = request.matchdict['user_id']
    notifications = notification_system.get_user_notifications(user_id)
    
    # Mark notifications as read when viewed
    for note in notification_system.notifications:
        if note['user_id'] == html.escape(user_id):
            note['read'] = True
    
    return {
        'user_id': html.escape(user_id),
        'notifications': notifications
    }

@view_config(route_name='mark_read', request_method='POST')
def mark_read_view(request):
    user_id = request.matchdict['user_id']
    for note in notification_system.notifications:
        if note['user_id'] == html.escape(user_id):
            note['read'] = True
    return Response("Notifications marked as read")

def make_app():
    with Configurator() as config:
        config.add_route('home', '/')
        config.add_route('add_notification', '/add_notification')
        config.add_route('view_notifications', '/notifications/{user_id}')
        config.add_route('mark_read', '/notifications/{user_id}/mark_read')
        
        # Configure template directory
        config.include('pyramid_jinja2')
        config.add_jinja2_renderer('.pt')
        config.add_static_view(name='static', path='static')
        
        config.scan()
    return config.make_wsgi_app()

# Create templates/notifications.pt with:
"""
<!DOCTYPE html>
<html>
<head>
    <title>Notifications for ${user_id}</title>
</head>
<body>
    <h1>Notifications for user ${user_id}</h1>
    <ul>
        % for note in notifications:
            <li class="${'read' if note['read'] else 'unread'}">
                ${note['message']}
            </li>
        % endfor
    </ul>
</body>
</html>
"""

if __name__ == '__main__':
    app = make_app()
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()