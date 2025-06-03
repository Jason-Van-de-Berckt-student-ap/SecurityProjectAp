"""
Monitoring and dashboard routes for the EASM application.
These routes provide system monitoring, logging, and performance dashboards.
"""
from flask import Blueprint, render_template, request, jsonify, g
from services.auth_service import require_permission, require_role
from services.logging_service import get_logging_service
import json
from datetime import datetime, timedelta

# Create blueprint
monitoring_bp = Blueprint('monitoring', __name__, url_prefix='/monitoring')

@monitoring_bp.route('/dashboard')
@require_permission('view_logs')
def dashboard():
    """Main monitoring dashboard."""
    logging_service = get_logging_service()
    
    # Get health data
    health_data = {
        'status': 'healthy',
        'system': {
            'cpu_percent': 25.4,  # Mock data - replace with actual psutil
            'memory_percent': 68.2,
            'disk_percent': 42.1
        }
    }
    
    # Get performance metrics
    performance_metrics = logging_service.get_performance_summary()
    
    # Get recent security events
    security_events = logging_service.get_recent_logs(
        log_type='security',
        limit=10
    )
    
    # Get user activities
    user_activities = logging_service.get_recent_logs(
        log_type='user_action',
        limit=15
    )
    
    # Get scan statistics
    scan_stats = logging_service.get_scan_statistics()
    
    return render_template('monitoring/dashboard.html',
                         health_data=health_data,
                         performance_metrics=performance_metrics,
                         security_events=security_events,
                         user_activities=user_activities,
                         scan_stats=scan_stats)

@monitoring_bp.route('/api/health')
@require_permission('system_health')
def system_health():
    """Get current system health status."""
    try:
        health_data = {}
        
        # Get health check service
        if hasattr(g, 'db_manager') and g.db_manager:
            health_data['database'] = {
                'status': 'healthy',
                'connections': g.db_manager.get_connection_count()
            }
        
        if hasattr(g, 'cache_manager') and g.cache_manager:
            health_data['cache'] = {
                'status': 'healthy',
                'memory_usage': g.cache_manager.get_memory_usage()
            }
        
        if hasattr(g, 'task_manager') and g.task_manager:
            health_data['background_tasks'] = {
                'status': 'healthy',
                'active_tasks': g.task_manager.get_active_task_count(),
                'queue_size': g.task_manager.get_queue_size()
            }
        
        return jsonify({
            'success': True,
            'health': health_data,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/api/logs')
@require_permission('view_logs')
def get_logs():
    """Get recent log events."""
    try:
        logging_service = get_logging_service()
        if not logging_service:
            return jsonify({'success': False, 'error': 'Logging service unavailable'}), 500
        
        # Get parameters
        event_type = request.args.get('event_type')
        limit = int(request.args.get('limit', 100))
        hours = int(request.args.get('hours', 24))
        
        # Get recent events
        events = logging_service.get_recent_events(event_type, limit)
        
        # Get statistics
        stats = logging_service.get_event_statistics(hours)
        
        return jsonify({
            'success': True,
            'events': events,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/api/performance')
@require_permission('view_logs')
def get_performance_metrics():
    """Get performance metrics."""
    try:
        logging_service = get_logging_service()
        if not logging_service:
            return jsonify({'success': False, 'error': 'Logging service unavailable'}), 500
        
        hours = int(request.args.get('hours', 24))
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get performance data from database
        performance_data = logging_service.db_manager.execute_query("""
            SELECT 
                DATE_TRUNC('hour', timestamp) as hour,
                AVG(duration) as avg_duration,
                COUNT(*) as request_count,
                COUNT(CASE WHEN level = 'ERROR' THEN 1 END) as error_count
            FROM log_events
            WHERE timestamp > %s AND event_type = 'performance_event'
            GROUP BY DATE_TRUNC('hour', timestamp)
            ORDER BY hour
        """, (cutoff_time,))
        
        # Get system health metrics
        system_health = logging_service.db_manager.execute_query("""
            SELECT *
            FROM system_health
            WHERE timestamp > %s
            ORDER BY timestamp DESC
            LIMIT 100
        """, (cutoff_time,))
        
        return jsonify({
            'success': True,
            'performance': performance_data,
            'system_health': system_health
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/api/security-events')
@require_permission('view_logs')
def get_security_events():
    """Get security events."""
    try:
        logging_service = get_logging_service()
        if not logging_service:
            return jsonify({'success': False, 'error': 'Logging service unavailable'}), 500
        
        hours = int(request.args.get('hours', 24))
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get security events
        security_events = logging_service.db_manager.execute_query("""
            SELECT *
            FROM log_events
            WHERE timestamp > %s 
            AND event_type = 'security_event'
            ORDER BY timestamp DESC
            LIMIT 100
        """, (cutoff_time,))
        
        return jsonify({
            'success': True,
            'security_events': security_events
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/api/user-activity')
@require_role('admin')
def get_user_activity():
    """Get user activity logs (admin only)."""
    try:
        logging_service = get_logging_service()
        if not logging_service:
            return jsonify({'success': False, 'error': 'Logging service unavailable'}), 500
        
        hours = int(request.args.get('hours', 24))
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get user activity
        user_activity = logging_service.db_manager.execute_query("""
            SELECT 
                username,
                action,
                resource,
                timestamp,
                ip_address,
                metadata
            FROM log_events
            WHERE timestamp > %s 
            AND event_type = 'user_action'
            AND username IS NOT NULL
            ORDER BY timestamp DESC
            LIMIT 200
        """, (cutoff_time,))
        
        # Get login statistics
        login_stats = logging_service.db_manager.execute_query("""
            SELECT 
                username,
                ip_address,
                success,
                COUNT(*) as attempt_count,
                MAX(attempted_at) as last_attempt
            FROM login_attempts
            WHERE attempted_at > %s
            GROUP BY username, ip_address, success
            ORDER BY last_attempt DESC
        """, (cutoff_time,))
        
        return jsonify({
            'success': True,
            'user_activity': user_activity,
            'login_statistics': login_stats
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/api/scan-statistics')
@require_permission('view_logs')
def get_scan_statistics():
    """Get scan performance statistics."""
    try:
        hours = int(request.args.get('hours', 24))
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get scan statistics from database
        scan_stats = g.db_manager.execute_query("""
            SELECT 
                COUNT(*) as total_scans,
                AVG(CASE WHEN dns_records != '' THEN 1 ELSE 0 END) * 100 as dns_success_rate,
                AVG(CASE WHEN ssl_info != '' THEN 1 ELSE 0 END) * 100 as ssl_success_rate,
                COUNT(CASE WHEN vulnerabilities != '[]' THEN 1 END) as scans_with_vulnerabilities,
                COUNT(DISTINCT domain) as unique_domains
            FROM scans
            WHERE scan_date > %s
        """, (cutoff_time,))
        
        # Get top scanned domains
        top_domains = g.db_manager.execute_query("""
            SELECT 
                domain,
                COUNT(*) as scan_count,
                MAX(scan_date) as last_scan
            FROM scans
            WHERE scan_date > %s
            GROUP BY domain
            ORDER BY scan_count DESC
            LIMIT 10
        """, (cutoff_time,))
        
        return jsonify({
            'success': True,
            'scan_statistics': scan_stats[0] if scan_stats else {},
            'top_domains': top_domains
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@monitoring_bp.route('/logs')
@require_permission('view_logs')
def logs_page():
    """Logs viewing page."""
    logging_service = get_logging_service()
    
    # Get filter parameters
    log_type = request.args.get('log_type')
    severity = request.args.get('severity')
    time_range = request.args.get('time_range', '24h')
    
    # Build filters
    filters = {}
    if severity:
        filters['severity'] = severity
    if time_range:
        filters['time_range'] = time_range
    
    # Get logs
    logs = logging_service.get_recent_logs(
        log_type=log_type,
        limit=100,
        **filters
    )
    
    return render_template('monitoring/logs.html', logs=logs)

@monitoring_bp.route('/logs/export')
@require_permission('view_logs')
def export_logs():
    """Export logs in CSV or JSON format."""
    from flask import Response
    import csv
    import io
    
    logging_service = get_logging_service()
    format_type = request.args.get('format', 'csv')
    
    # Get filter parameters
    log_type = request.args.get('log_type')
    severity = request.args.get('severity')
    time_range = request.args.get('time_range', '24h')
    
    # Build filters
    filters = {}
    if severity:
        filters['severity'] = severity
    if time_range:
        filters['time_range'] = time_range
    
    # Get logs
    logs = logging_service.get_recent_logs(
        log_type=log_type,
        limit=1000,
        **filters
    )
    
    if format_type == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Timestamp', 'Type', 'Severity', 'User', 'Action', 'Resource', 'IP Address', 'Details'])
        
        # Write data
        for log in logs:
            writer.writerow([
                log.get('timestamp', ''),
                log.get('log_type', ''),
                log.get('severity', ''),
                log.get('username', ''),
                log.get('action', ''),
                log.get('resource', ''),
                log.get('ip_address', ''),
                log.get('details', '')
            ])
        
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={"Content-Disposition": f"attachment;filename=logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"}
        )
    
    else:  # JSON format
        return jsonify({
            'logs': logs,
            'exported_at': datetime.now().isoformat(),
            'filters': {'log_type': log_type, 'severity': severity, 'time_range': time_range}
        })

@monitoring_bp.route('/performance')
@require_permission('view_logs')
def performance_page():
    """Performance monitoring page."""
    return render_template('monitoring/performance.html')

@monitoring_bp.route('/security')
@require_permission('view_logs')
def security_page():
    """Security monitoring page."""
    return render_template('monitoring/security.html')

@monitoring_bp.route('/users')
@require_role('admin')
def users_page():
    """User management page (admin only)."""
    from services.auth_service import get_auth_service
    
    auth_service = get_auth_service()
    users = auth_service.get_all_users()
    
    # Calculate user statistics
    user_stats = {
        'total_users': len(users),
        'active_users': len([u for u in users if u.is_active]),
        'admin_users': len([u for u in users if u.role == 'admin']),
        'recent_logins': len([u for u in users if u.last_login and 
                             (datetime.now() - u.last_login).days < 7])
    }
    
    return render_template('monitoring/users.html', users=users, user_stats=user_stats)

@monitoring_bp.route('/users/create', methods=['POST'])
@require_role('admin')
def create_user():
    """Create a new user."""
    from services.auth_service import get_auth_service
    
    try:
        auth_service = get_auth_service()
        
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role', 'user')
        
        if not username or not password:
            return jsonify({'success': False, 'error': 'Username and password are required'})
        
        # Create user
        user = auth_service.create_user(username, password, email, role)
        if user:
            return jsonify({'success': True, 'message': f'User {username} created successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to create user'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@monitoring_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@require_role('admin')
def delete_user(user_id):
    """Delete a user."""
    from services.auth_service import get_auth_service
    
    try:
        auth_service = get_auth_service()
        
        # Don't allow deleting current user
        if user_id == g.current_user.id:
            return jsonify({'success': False, 'error': 'Cannot delete current user'})
        
        success = auth_service.delete_user(user_id)
        if success:
            return jsonify({'success': True, 'message': 'User deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete user'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@monitoring_bp.route('/users/<int:user_id>/toggle', methods=['POST'])
@require_role('admin')
def toggle_user_status(user_id):
    """Enable/disable a user."""
    from services.auth_service import get_auth_service
    
    try:
        auth_service = get_auth_service()
        
        # Don't allow disabling current user
        if user_id == g.current_user.id:
            return jsonify({'success': False, 'error': 'Cannot disable current user'})
        
        success = auth_service.toggle_user_status(user_id)
        if success:
            return jsonify({'success': True, 'message': 'User status updated successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to update user status'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
