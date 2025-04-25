from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from firebase_admin import credentials, initialize_app, db
from datetime import datetime, timedelta
import os
from functools import wraps

# Firebase Initialization
cred = credentials.Certificate(
    r"C:\Users\Ashik\PycharmProjects\DATA_TRACKER\backend\rcil-data-collector-firebase-adminsdk-fbsvc-0344f2ffac.json"
)
initialize_app(cred, {
    'databaseURL': 'https://rcil-data-collector-default-rtdb.firebaseio.com/'
})

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:;"
    return response

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting decorator
def rate_limit(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Implement rate limiting logic here
        # For example, limit to 100 requests per minute per IP
        return f(*args, **kwargs)
    return decorated_function

# Admin credentials
ADMIN_USERNAME = 'RCIL_DATA_TRACK'
ADMIN_PASSWORD = 'RCIL_77366'


@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the credentials match admin credentials
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin'] = username
            session.permanent = True
            return redirect(url_for('admin_panel'))

        # Check regular user credentials
        ref = db.reference('users')
        users_data = ref.get()

        if users_data:
            for user_id, user in users_data.items():
                if user.get('username') == username and user.get('password') == password:
                    session['username'] = username
                    return redirect(url_for('dashboard'))

        return render_template('login.html', error="Invalid username or password.")

    return render_template('login.html', error=None)


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Admin login attempt - Username: {username}")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            print("Admin login successful")
            session['admin'] = username
            session.permanent = True  # Make session permanent
            return redirect(url_for('admin_panel'))

        print("Admin login failed - Invalid credentials")
        return render_template('admin_login.html', error="Invalid Credentials")

    return render_template('admin_login.html')


@app.route('/admin_panel')
def admin_panel():
    if 'admin' not in session:
        print("Admin not in session, redirecting to login")
        return redirect(url_for('admin_login'))
    print("Admin in session, rendering admin panel")
    return render_template('index.html')


@app.route('/create_user', methods=['POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        branches = request.form.getlist('branches[]')

        ref = db.reference('users')
        user_data = {
            'username': username,
            'password': password,
            'branches': branches
        }

        ref.push(user_data)
        return redirect(url_for('admin_panel'))


@app.route('/get_users', methods=['GET'])
def get_users():
    ref = db.reference('users')
    users_data = ref.get()

    user_list = []
    if users_data:
        for user_id, user in users_data.items():
            user_list.append({
                "username": user.get("username", "Unknown"),
                "branches": user.get("branches", [])
            })

    return jsonify({"users": user_list})


@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('login'))


@app.route('/marketing', methods=['GET', 'POST'])
def marketing():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get user data from Firebase to fetch the allocated branches
    ref = db.reference('users')
    users_data = ref.get()

    user_branches = []
    if users_data:
        for user_id, user in users_data.items():
            if user.get('username') == session['username']:
                # Extract the branches for the logged-in user
                user_branches = user.get('branches', [])

    ref = db.reference('marketing_entries')

    if request.method == 'POST':
        data = {
            "username": session['username'],
            "branch": request.form['branch'],
            "staff": request.form.getlist('staff'),
            "marketing_type": request.form['marketing_type'],
            "location": request.form['location'],
            "start_time": request.form['start_time'],
            "end_time": request.form['end_time']
        }
        ref.push(data)

    # Get all marketing entries
    entries = ref.order_by_key().get()
    entry_list = list(entries.values()) if entries else []

    return render_template('marketing.html', username=session['username'], entries=entry_list, user_branches=user_branches)


@app.route('/reference_register', methods=['GET'])
def reference_register():
    if 'username' not in session:
        return redirect(url_for('login'))

    current_time = datetime.now().strftime('%Y-%m-%dT%H:%M')
    ref = db.reference('users')

    # Fetch all users' data
    users_data = ref.get()

    user_branches = []
    if users_data:
        # Find the current logged-in user
        for user_id, user in users_data.items():
            if user.get('username') == session['username']:
                # Extract the branches for the logged-in user
                user_branches = user.get('branches', [])

    return render_template('reference_register.html', current_time=current_time, user_branches=user_branches)


@app.route('/submit_reference', methods=['POST'])
def submit_reference():
    if 'username' not in session:
        return redirect(url_for('login'))

    try:
        # Get and validate form data
        reference_name = request.form['reference_name'].strip()
        contact = request.form['contact'].strip()
        branch = request.form['branch'].strip()
        referred_by = request.form['referred_by'].strip()
        remarks = request.form['remarks'].strip()
        datetime = request.form['datetime'].strip()

        # Input validation
        if not all([reference_name, contact, branch, referred_by, datetime]):
            return render_template('reference_register.html', error="All fields are required")

        # Validate contact number (basic validation)
        if not contact.isdigit() or len(contact) < 10:
            return render_template('reference_register.html', error="Invalid contact number")

        # Store in Firebase under 'reference_entries'
        ref = db.reference('reference_entries')

        data = {
            "username": session['username'],
            "reference_name": reference_name,
            "contact_number": contact,
            "branch": branch,
            "referred_by": referred_by,
            "remarks": remarks,
            "datetime": datetime
        }

        ref.push(data)
        return redirect(url_for('dashboard'))

    except Exception as e:
        return render_template('reference_register.html', error=f"Error occurred: {str(e)}")


@app.route('/area_managers', methods=['GET'])
def area_managers():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get user data from Firebase to fetch the allocated branches
    ref = db.reference('users')
    users_data = ref.get()

    user_branches = []
    if users_data:
        for user_id, user in users_data.items():
            if user.get('username') == session['username']:
                user_branches = user.get('branches', [])

    return render_template('area_managers.html', user_branches=user_branches)


@app.route('/submit_area_manager', methods=['POST'])
def submit_area_manager():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.get_json()
        
        # Store in Firebase under 'area_manager_entries'
        ref = db.reference('area_manager_entries')
        
        # Add timestamp and username
        data['timestamp'] = datetime.now().isoformat()
        
        ref.push(data)
        return jsonify({'success': True}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin_area_managers')
def admin_area_managers():
    if 'admin' not in session:
        return redirect(url_for('admin_login'))

    # Get all area manager entries from Firebase
    ref = db.reference('area_manager_entries')
    entries = ref.get()
    
    # Convert entries to list and sort by timestamp
    entries_list = []
    if entries:
        for entry_id, entry in entries.items():
            entry['id'] = entry_id
            entries_list.append(entry)
        
        # Sort by timestamp in descending order (newest first)
        entries_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return render_template('admin_area_managers.html', entries=entries_list)


@app.route('/delete_area_manager/<entry_id>', methods=['DELETE'])
def delete_area_manager(entry_id):
    if 'admin' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        ref = db.reference('area_manager_entries')
        ref.child(entry_id).delete()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/collection_tracker', methods=['GET'])
def collection_tracker():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Get user data from Firebase to fetch the allocated branches
    ref = db.reference('users')
    users_data = ref.get()

    user_branches = []
    if users_data:
        for user_id, user in users_data.items():
            if user.get('username') == session['username']:
                user_branches = user.get('branches', [])

    return render_template('collection_tracker.html', user_branches=user_branches)

@app.route('/submit_collection', methods=['POST'])
def submit_collection():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.get_json()
        
        # Store collection data in Firebase
        ref = db.reference('collection_entries')
        ref.push({
            'username': data['username'],
            'centers': data['centers'],
            'total_amount': data['totalAmount'],
            'total_distance': data['totalDistance'],
            'centers_visited': data['centersVisited'],
            'timestamp': data['timestamp']
        })

        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_branch_data')
def get_branch_data():
    if 'username' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        # Get all branches
        ref = db.reference('users')
        users_data = ref.get()
        
        # Get user's branches
        user_branches = []
        if users_data:
            for user_id, user in users_data.items():
                if user.get('username') == session['username']:
                    user_branches = user.get('branches', [])
                    break

        # Get marketing entries
        marketing_ref = db.reference('marketing_entries')
        marketing_data = marketing_ref.get() or {}
        
        # Get reference entries
        reference_ref = db.reference('reference_entries')
        reference_data = reference_ref.get() or {}

        # Initialize counts for each branch
        marketing_counts = {branch: 0 for branch in user_branches}
        reference_counts = {branch: 0 for branch in user_branches}

        # Count marketing entries by branch
        for entry in marketing_data.values():
            branch = entry.get('branch')
            if branch in user_branches:
                marketing_counts[branch] += 1

        # Count reference entries by branch
        for entry in reference_data.values():
            branch = entry.get('branch')
            if branch in user_branches:
                reference_counts[branch] += 1

        return jsonify({
            'branches': user_branches,
            'marketing_counts': [marketing_counts[branch] for branch in user_branches],
            'reference_counts': [reference_counts[branch] for branch in user_branches]
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/get_user_summary')
def get_user_summary():
    if 'admin' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        time_filter = request.args.get('time', 'all')
        today = datetime.now().date()
        
        # Get all users
        ref = db.reference('users')
        users_data = ref.get() or {}
        
        # Get marketing entries
        marketing_ref = db.reference('marketing_entries')
        marketing_data = marketing_ref.get() or {}
        
        # Get reference entries
        reference_ref = db.reference('reference_entries')
        reference_data = reference_ref.get() or {}

        user_summaries = []
        for user_id, user in users_data.items():
            username = user.get('username')
            if not username:
                continue

            # Filter entries based on time period
            def filter_by_time(entry):
                entry_date = datetime.fromisoformat(entry.get('timestamp', '')).date()
                if time_filter == 'today':
                    return entry_date == today
                elif time_filter == 'week':
                    return (today - entry_date).days <= 7
                elif time_filter == 'month':
                    return (today - entry_date).days <= 30
                return True

            # Count marketing entries for this user
            marketing_count = sum(1 for entry in marketing_data.values() 
                                if entry.get('username') == username and filter_by_time(entry))

            # Count reference entries for this user
            reference_count = sum(1 for entry in reference_data.values() 
                                if entry.get('username') == username and filter_by_time(entry))

            user_summaries.append({
                'username': username,
                'marketing_count': marketing_count,
                'reference_count': reference_count
            })

        return jsonify({'users': user_summaries})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('error.html', error="Internal server error"), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error="Access forbidden"), 403


if __name__ == '__main__':
    app.run(debug=False)  # Set debug to False in production
