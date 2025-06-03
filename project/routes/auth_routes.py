"""
Authentication routes for the EASM application.
These routes handle user login, logout, registration, and profile management.
"""
from flask import Blueprint, request, jsonify, session, render_template, redirect, url_for, flash, g
from services.auth_service import get_auth_service
import logging

logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if request.method == 'GET':
        return render_template('auth/login.html')
    
    try:
        # Get form data
        data = request.get_json() if request.is_json else request.form
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Username and password are required'}), 400
            flash('Username and password are required', 'error')
            return render_template('auth/login.html')
        
        # Get client info
        ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
        user_agent = request.headers.get('User-Agent', '')
        
        # Authenticate user
        auth_service = get_auth_service()
        if not auth_service:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Authentication service unavailable'}), 500
            flash('Authentication service unavailable', 'error')
            return render_template('auth/login.html')
        
        result = auth_service.authenticate_user(username, password, ip_address, user_agent)
        
        if result['success']:
            # Set session
            session['session_id'] = result['session_id']
            session['user_id'] = result['user']['user_id']
            session['username'] = result['user']['username']
            session['role'] = result['user']['role']
            
            logger.info(f"User {username} logged in successfully")
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'user': result['user'],
                    'session_id': result['session_id']
                })
            
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('single_scan.index'))
        else:
            logger.warning(f"Failed login attempt for {username}: {result['error']}")
            
            if request.is_json:
                return jsonify(result), 401
            
            flash(result['error'], 'error')
            return render_template('auth/login.html')
    
    except Exception as e:
        logger.error(f"Login error: {e}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Login failed'}), 500
        flash('Login failed', 'error')
        return render_template('auth/login.html')

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """User logout route."""
    try:
        session_id = session.get('session_id')
        user_id = session.get('user_id')
        
        if session_id and user_id:
            auth_service = get_auth_service()
            if auth_service:
                ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
                auth_service.logout_user(session_id, user_id, ip_address)
        
        # Clear session
        session.clear()
        
        if request.is_json:
            return jsonify({'success': True, 'message': 'Logged out successfully'})
        
        flash('You have been logged out', 'info')
        return redirect(url_for('auth.login'))
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Logout failed'}), 500
        flash('Logout failed', 'error')
        return redirect(url_for('single_scan.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if request.method == 'GET':
        return render_template('auth/register.html')
    
    try:
        # Get form data
        data = request.get_json() if request.is_json else request.form
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')
        
        # Validation
        if not username or not email or not password:
            error = 'Username, email, and password are required'
            if request.is_json:
                return jsonify({'success': False, 'error': error}), 400
            flash(error, 'error')
            return render_template('auth/register.html')
        
        if password != confirm_password:
            error = 'Passwords do not match'
            if request.is_json:
                return jsonify({'success': False, 'error': error}), 400
            flash(error, 'error')
            return render_template('auth/register.html')
        
        # Create user
        auth_service = get_auth_service()
        if not auth_service:
            if request.is_json:
                return jsonify({'success': False, 'error': 'Authentication service unavailable'}), 500
            flash('Authentication service unavailable', 'error')
            return render_template('auth/register.html')
        
        result = auth_service.create_user(username, email, password, role='user')
        
        if result['success']:
            logger.info(f"User {username} registered successfully")
            
            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'User created successfully',
                    'user_id': result['user_id']
                })
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            if request.is_json:
                return jsonify(result), 400
            flash(result['error'], 'error')
            return render_template('auth/register.html')
    
    except Exception as e:
        logger.error(f"Registration error: {e}")
        if request.is_json:
            return jsonify({'success': False, 'error': 'Registration failed'}), 500
        flash('Registration failed', 'error')
        return render_template('auth/register.html')

@auth_bp.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile route."""
    from services.auth_service import login_required
    
    @login_required
    def view_profile():
        if request.method == 'GET':
            if request.is_json:
                return jsonify({'success': True, 'user': g.current_user.to_dict()})
            return render_template('auth/profile.html', user=g.current_user)
        
        # Update profile
        try:
            data = request.get_json() if request.is_json else request.form
            # Profile update logic can be added here
            
            if request.is_json:
                return jsonify({'success': True, 'message': 'Profile updated successfully'})
            flash('Profile updated successfully', 'success')
            return render_template('auth/profile.html', user=g.current_user)
        
        except Exception as e:
            logger.error(f"Profile update error: {e}")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Profile update failed'}), 500
            flash('Profile update failed', 'error')
            return render_template('auth/profile.html', user=g.current_user)
    
    return view_profile()

@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    """Change user password route."""
    from services.auth_service import login_required
    
    @login_required
    def change_user_password():
        try:
            data = request.get_json() if request.is_json else request.form
            current_password = data.get('current_password', '')
            new_password = data.get('new_password', '')
            confirm_password = data.get('confirm_password', '')
            
            if not current_password or not new_password:
                error = 'Current password and new password are required'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return redirect(url_for('auth.profile'))
            
            if new_password != confirm_password:
                error = 'New passwords do not match'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return redirect(url_for('auth.profile'))
            
            if len(new_password) < 8:
                error = 'New password must be at least 8 characters'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return redirect(url_for('auth.profile'))
            
            # Verify current password and update
            auth_service = get_auth_service()
            if not auth_service:
                if request.is_json:
                    return jsonify({'success': False, 'error': 'Service unavailable'}), 500
                flash('Service unavailable', 'error')
                return redirect(url_for('auth.profile'))
            
            # Get current user data
            user_data = auth_service.db_manager.execute_query(
                "SELECT password_hash, salt FROM users WHERE user_id = %s",
                (g.current_user.user_id,)
            )
            
            if not user_data:
                error = 'User not found'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 404
                flash(error, 'error')
                return redirect(url_for('auth.profile'))
            
            # Verify current password
            if not auth_service.verify_password(current_password, user_data[0]['password_hash'], user_data[0]['salt']):
                error = 'Current password is incorrect'
                if request.is_json:
                    return jsonify({'success': False, 'error': error}), 400
                flash(error, 'error')
                return redirect(url_for('auth.profile'))
            
            # Update password
            new_hash, new_salt = auth_service.hash_password(new_password)
            auth_service.db_manager.execute_query(
                "UPDATE users SET password_hash = %s, salt = %s WHERE user_id = %s",
                (new_hash, new_salt, g.current_user.user_id)
            )
            
            # Log audit event
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            auth_service._log_audit_event(
                g.current_user.user_id, 'password_change', 'user', 'Password changed', ip_address
            )
            
            logger.info(f"Password changed for user {g.current_user.username}")
            
            if request.is_json:
                return jsonify({'success': True, 'message': 'Password changed successfully'})
            flash('Password changed successfully', 'success')
            return redirect(url_for('auth.profile'))
        
        except Exception as e:
            logger.error(f"Password change error: {e}")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Password change failed'}), 500
            flash('Password change failed', 'error')
            return redirect(url_for('auth.profile'))
    
    return change_user_password()

@auth_bp.route('/api/token', methods=['POST'])
def get_api_token():
    """Get JWT token for API access."""
    from services.auth_service import login_required
    
    @login_required
    def generate_token():
        try:
            auth_service = get_auth_service()
            if not auth_service:
                return jsonify({'success': False, 'error': 'Service unavailable'}), 500
            
            token = auth_service.generate_jwt_token(g.current_user)
            
            # Log audit event
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            auth_service._log_audit_event(
                g.current_user.user_id, 'token_generation', 'api', 'API token generated', ip_address
            )
            
            return jsonify({
                'success': True,
                'token': token,
                'expires_in': 3600  # 1 hour
            })
        
        except Exception as e:
            logger.error(f"Token generation error: {e}")
            return jsonify({'success': False, 'error': 'Token generation failed'}), 500
    
    return generate_token()

@auth_bp.route('/admin/users', methods=['GET'])
def admin_users():
    """Admin route to view all users."""
    from services.auth_service import require_role
    
    @require_role('admin')
    def list_users():
        try:
            auth_service = get_auth_service()
            if not auth_service:
                return jsonify({'success': False, 'error': 'Service unavailable'}), 500
            
            users = auth_service.db_manager.execute_query("""
                SELECT user_id, username, email, role, created_at, last_login, is_active
                FROM users ORDER BY created_at DESC
            """)
            
            user_list = []
            for user in users:
                user_list.append({
                    'user_id': user['user_id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role'],
                    'created_at': user['created_at'].isoformat() if user['created_at'] else None,
                    'last_login': user['last_login'].isoformat() if user['last_login'] else None,
                    'is_active': user['is_active']
                })
            
            if request.is_json:
                return jsonify({'success': True, 'users': user_list})
            
            return render_template('auth/admin_users.html', users=user_list)
        
        except Exception as e:
            logger.error(f"Admin users error: {e}")
            if request.is_json:
                return jsonify({'success': False, 'error': 'Failed to fetch users'}), 500
            flash('Failed to fetch users', 'error')
            return redirect(url_for('single_scan.index'))
    
    return list_users()

@auth_bp.route('/check-auth', methods=['GET'])
def check_auth():
    """Check authentication status."""
    session_id = session.get('session_id')
    
    if not session_id:
        return jsonify({'authenticated': False})
    
    auth_service = get_auth_service()
    if not auth_service:
        return jsonify({'authenticated': False})
    
    user_id = auth_service.validate_session(session_id)
    if user_id:
        user = auth_service.get_user(user_id)
        if user:
            return jsonify({
                'authenticated': True,
                'user': user.to_dict()
            })
    
    return jsonify({'authenticated': False})
