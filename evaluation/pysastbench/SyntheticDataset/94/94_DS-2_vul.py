from bottle import Bottle, request, response, template
import json

app = Bottle()
DATA_FILE = 'user_data.json'

def init_data():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'w') as f:
            json.dump({"users": []}, f)

def load_data():
    with open(DATA_FILE) as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

def vulnerable_filter(data, filter_expr):
    """Vulnerable function with code injection"""
    filtered = []
    for item in data:
        try:
            # Dangerous eval of user-controlled filter expression
            if eval(filter_expr, {}, {'item': item}):  # Code injection point
                filtered.append(item)
        except:
            continue
    return filtered

@app.route('/')
def index():
    return '''
        <form action="/search" method="post">
            <h2>User Search</h2>
            Name: <input name="name" type="text"><br>
            Age: <input name="age" type="number"><br>
            Filter Expression (Python): 
            <input name="filter" type="text" placeholder="e.g., item['age'] > 18"><br>
            <button type="submit">Search</button>
        </form>
        <a href="/users">View All Users</a>
    '''

@app.route('/users')
def list_users():
    data = load_data()
    return template('''
        <h2>All Users</h2>
        <ul>
            %for user in data['users']:
                <li>{{user['name']}} ({{user['age']}})</li>
            %end
        </ul>
    ''', data=data)

@app.post('/search')
def search_users():
    data = load_data()
    filter_expr = request.forms.get('filter', 'True')
    
    # Vulnerable code execution
    results = vulnerable_filter(data['users'], filter_expr)
    
    return template('''
        <h2>Search Results</h2>
        <ul>
            %for user in results:
                <li>{{user['name']}} ({{user['age']}})</li>
            %end
        </ul>
        <a href="/">New Search</a>
    ''', results=results)

@app.post('/add')
def add_user():
    data = load_data()
    data['users'].append({
        'name': request.forms.get('name'),
        'age': int(request.forms.get('age'))
    })
    save_data(data)
    return "User added successfully!"

if __name__ == '__main__':
    import os
    init_data()
    app.run(host='localhost', port=8080, debug=True)