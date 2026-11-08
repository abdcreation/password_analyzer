"""
Password Strength Analyzer & Secure Authentication System
Main Flask Application with Security Middleware, REST APIs, and Protected Dashboards.
"""

import io
import csv
import functools
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    Response
)
from config import Config
from database import (
    init_db,
    get_user_by_id,
    get_all_users,
    update_user_lock_state,
    get_user_login_history,
    get_audit_logs,
    get_security_alerts,
    get_aggregate_security_metrics,
    record_login_attempt
)
from security.auth import (
    authenticate_user,
    register_user_account,
    update_password
)
from security.analyzer import (
    analyze_password,
    generate_secure_password
)

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database is created on startup
with app.app_context():
    init_db()

def get_client_ip() -> str:
    """Extracts client IP address safely considering reverse proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

# ----------------- Authentication Decorators -----------------

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("Please sign in to access your security dashboard.", "warning")
            return redirect(url_for('login', next=request.path))
        return view(**kwargs)
    return wrapped_view

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("Administrator login required.", "warning")
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            flash("Access denied: Administrator privileges required.", "danger")
            return redirect(url_for('dashboard'))
        return view(**kwargs)
    return wrapped_view

# ----------------- Web Page Routes -----------------

@app.route('/')
def index():
    """Landing page featuring application overview and live quick analyzer."""
    return render_template('index.html')

@app.route('/analyzer')
def standalone_analyzer():
    """Dedicated full-suite Password Strength Analyzer interface."""
    return render_template('analyzer.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration with real-time password strength validation."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', username=username, email=email)

        success, message, user_id = register_user_account(username, email, password, role='user')
        if success:
            flash("Account successfully created! You can now log in.", "success")
            return redirect(url_for('login'))
        else:
            flash(message, "danger")
            return render_template('register.html', username=username, email=email)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure user login with brute-force protection and lockout monitoring."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        ip_address = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Unknown')

        success, user, message = authenticate_user(username, password, ip_address, user_agent)

        if success and user:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = True
            flash(f"Welcome back, {user['username']}! Authenticated successfully.", "success")
            
            next_url = request.args.get('next')
            if next_url and next_url.startswith('/'):
                return redirect(next_url)
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash(message, "danger")
            return render_template('login.html', username=username)

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Clears user session and logs out."""
    username = session.get('username', 'Anonymous')
    session.clear()
    flash(f"You have been safely signed out. See you next time, {username}!", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User security dashboard displaying password strength score and personal logs."""
    user = get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))

    history = get_user_login_history(user['username'], limit=15)
    return render_template('dashboard.html', user=user, history=history)

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Secure password change with validation and strength re-calculation."""
    user = get_user_by_id(session['user_id'])
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return render_template('change_password.html', user=user)

        success, message = update_password(user['id'], current_password, new_password)
        if success:
            flash("Password updated successfully! Your security score has been recalculated.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash(message, "danger")

    return render_template('change_password.html', user=user)

@app.route('/admin')
@admin_required
def admin_dashboard():
    """Security Operations Center (SOC) Admin Dashboard."""
    users = get_all_users()
    metrics = get_aggregate_security_metrics()
    alerts = get_security_alerts(limit=15)
    logs = get_audit_logs(limit=25)
    return render_template('admin.html', users=users, metrics=metrics, alerts=alerts, logs=logs)

@app.route('/admin/toggle-lock/<int:user_id>', methods=['POST'])
@admin_required
def toggle_user_lock(user_id):
    """Admin action to manually lock or unlock a user account."""
    user = get_user_by_id(user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Prevent locking oneself out
    if user['id'] == session.get('user_id'):
        flash("Action prohibited: You cannot lock your own administrator account.", "warning")
        return redirect(url_for('admin_dashboard'))

    new_state = not bool(user['is_locked'])
    update_user_lock_state(user['id'], is_locked=new_state, locked_until=None if not new_state else "2099-12-31 23:59:59", failed_attempts=0 if not new_state else 5)
    
    action_str = "locked" if new_state else "unlocked"
    flash(f"Account '{user['username']}' has been manually {action_str} by administrator.", "info")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/export-logs')
@admin_required
def export_audit_logs():
    """Exports security audit logs to downloadable CSV."""
    logs = get_audit_logs(limit=1000)
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp (UTC)", "Username", "IP Address", "Status", "Failure Reason", "User Agent"])
    
    for row in logs:
        writer.writerow([
            row['id'],
            row['timestamp'],
            row['username'],
            row['ip_address'],
            row['status'],
            row['failure_reason'] or '',
            row['user_agent']
        ])
        
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=security_audit_logs.csv"}
    )

# ----------------- REST API Endpoints -----------------

@app.route('/api/analyze-password', methods=['POST'])
def api_analyze_password():
    """Real-time password evaluation API."""
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')
    result = analyze_password(password)
    return jsonify(result)

@app.route('/api/generate-password', methods=['GET'])
def api_generate_password():
    """Generates cryptographically random high-entropy passwords."""
    try:
        length = int(request.args.get('length', 16))
    except ValueError:
        length = 16
        
    use_upper = request.args.get('upper', 'true').lower() == 'true'
    use_digits = request.args.get('digits', 'true').lower() == 'true'
    use_symbols = request.args.get('symbols', 'true').lower() == 'true'

    pwd = generate_secure_password(
        length=length,
        use_upper=use_upper,
        use_digits=use_digits,
        use_symbols=use_symbols
    )
    analysis = analyze_password(pwd)
    return jsonify({
        "password": pwd,
        "analysis": analysis
    })

@app.route('/api/security-stats', methods=['GET'])
@admin_required
def api_security_stats():
    """Returns analytics data for Chart.js rendering."""
    metrics = get_aggregate_security_metrics()
    return jsonify(metrics)

@app.route('/api/audit-logs', methods=['GET'])
@admin_required
def api_audit_logs():
    """Returns filtered audit logs."""
    limit = int(request.args.get('limit', 50))
    status = request.args.get('status')
    search = request.args.get('search')
    logs = get_audit_logs(limit=limit, status_filter=status, search=search)
    return jsonify([dict(r) for r in logs])

# ----------------- Error Handlers -----------------

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    # Local development server
    app.run(host='127.0.0.1', port=5000, debug=True)
