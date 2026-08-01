from pyramid.config import Configurator
from pyramid.response import Response
from pyramid.view import view_config
from wsgiref.simple_server import make_server
import html

class NotificationSystem:
    def __init__(self):
        self.notifications = []
    
    def add_notification(self, user_id, message):
        self.notifications.append({
            'user_id': user_id,
            'message': message,
            'read': False
        })
    
    def get_user_notifications(self, user_id):
        return [n for n in self.notifications if n['user_id'] == user_id]

notification_system = NotificationSystem()

@view_config(route_name='home', renderer='string')
def home_view(request):
    return "Welcome to the notification system. Visit /notifications/<user_id>"

@view_config(route_name='add_notification', request_method='POST')
def add_notification_view(request):
    user_id = request.POST.get('user_id')
    message = request.POST.get('message')
    
    if user_id and message:
        notification_system.add_notification(user_id, message)
        return Response("Notification added")
    return Response("Invalid input", status=400)

@view_config(route_name='view_notifications')
def view_notifications_view(request):
    user_id = request.matchdict['user_id']
    
    # Vulnerable function - renders notifications without proper escaping
    def render_notifications(notifications):
        html = f"<h1>Notifications for user {user_id}</h1><ul>"
        for note in notifications:
            status = "read" if note['read'] else "unread"
            html += f"<li class='{status}'>" + note['message'] + "</li>"
        html += "</ul>"
        return html
    
    notifications = notification_system.get_user_notifications(user_id)
    return Response(render_notifications(notifications))

@view_config(route_name='mark_read', request_method='POST')
def mark_read_view(request):
    user_id = request.matchdict['user_id']
    for note in notification_system.notifications:
        if note['user_id'] == user_id:
            note['read'] = True
    return Response("Notifications marked as read")

def make_app():
    with Configurator() as config:
        config.add_route('home', '/')
        config.add_route('add_notification', '/add_notification')
        config.add_route('view_notifications', '/notifications/{user_id}')
        config.add_route('mark_read', '/notifications/{user_id}/mark_read')
        config.scan()
    return config.make_wsgi_app()

if __name__ == '__main__':
    app = make_app()
    server = make_server('0.0.0.0', 6543, app)
    server.serve_forever()