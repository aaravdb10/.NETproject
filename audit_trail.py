"""
Comprehensive Audit Trail System for RBAC Application

This module implements a detailed audit logging system that tracks all user actions,
security events, and system changes for compliance and security monitoring.

Features:
1. Detailed audit logging with enhanced metadata
2. Admin dashboard for viewing audit logs
3. Security event tracking and analysis
4. Compliance reporting capabilities
"""

import sqlite3
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from flask import request
import logging

# Configure audit logging
audit_logger = logging.getLogger('audit_trail')
audit_logger.setLevel(logging.INFO)

class AuditTrailManager:
    """
    Comprehensive audit trail manager for tracking all system activities.
    """
    
    def __init__(self, database_path: str):
        """
        Initialize audit trail manager.
        
        Args:
            database_path: Path to SQLite database
        """
        self.database_path = database_path
        self._init_audit_tables()
    
    def _init_audit_tables(self):
        """Initialize enhanced audit tables"""
        conn = sqlite3.connect(self.database_path)
        
        # Enhanced audit log table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS enhanced_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT,
                user_role TEXT,
                action_category TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_details TEXT,
                target_resource_type TEXT,
                target_resource_id TEXT,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                user_agent TEXT,
                session_id TEXT,
                request_method TEXT,
                request_url TEXT,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                risk_level TEXT DEFAULT 'low',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Security events table for specific security-related activities
        conn.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                username TEXT,
                description TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                severity TEXT DEFAULT 'info',
                additional_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Login attempts table for authentication tracking
        conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                email TEXT,
                ip_address TEXT,
                user_agent TEXT,
                success BOOLEAN,
                failure_reason TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_user_action(self, user_id: Optional[int], username: str, user_role: str,
                       action_category: str, action_type: str, action_details: str = None,
                       target_resource_type: str = None, target_resource_id: str = None,
                       old_values: Dict = None, new_values: Dict = None,
                       success: bool = True, error_message: str = None,
                       risk_level: str = 'low') -> bool:
        """
        Log comprehensive user action with full context.
        
        Args:
            user_id: ID of user performing action
            username: Username of user
            user_role: Role of user
            action_category: Category of action (auth, user_mgmt, data_access)
            action_type: Specific action (login, create_user, update_profile)
            action_details: Additional details about the action
            target_resource_type: Type of resource being accessed
            target_resource_id: ID of resource being accessed
            old_values: Previous values before change
            new_values: New values after change
            success: Whether action was successful
            error_message: Error message if action failed
            risk_level: Risk level (low, medium, high, critical)
            
        Returns:
            bool: True if logged successfully
        """
        try:
            # Get request context
            ip_address = self._get_client_ip()
            user_agent = self._get_user_agent()
            session_id = self._get_session_id()
            request_method = getattr(request, 'method', 'UNKNOWN')
            request_url = getattr(request, 'url', 'UNKNOWN')
            
            conn = sqlite3.connect(self.database_path)
            
            conn.execute('''
                INSERT INTO enhanced_audit_log 
                (user_id, username, user_role, action_category, action_type, action_details,
                 target_resource_type, target_resource_id, old_values, new_values,
                 ip_address, user_agent, session_id, request_method, request_url,
                 success, error_message, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, user_role, action_category, action_type, action_details,
                  target_resource_type, target_resource_id,
                  json.dumps(old_values) if old_values else None,
                  json.dumps(new_values) if new_values else None,
                  ip_address, user_agent, session_id, request_method, request_url,
                  success, error_message, risk_level))
            
            conn.commit()
            conn.close()
            
            # Also log to application logger
            log_level = 'INFO' if success else 'WARNING'
            audit_logger.log(
                getattr(logging, log_level),
                f"AUDIT: {username}({user_role}) - {action_category}.{action_type} - {action_details}"
            )
            
            return True
            
        except Exception as e:
            audit_logger.error(f"Failed to log audit action: {e}")
            return False
    
    def log_security_event(self, event_type: str, user_id: Optional[int], username: str,
                          description: str, severity: str = 'info',
                          additional_data: Dict = None) -> bool:
        """
        Log security-related events.
        
        Args:
            event_type: Type of security event
            user_id: User ID if applicable
            username: Username if applicable
            description: Description of the event
            severity: Severity level (info, warning, critical)
            additional_data: Additional data as dict
            
        Returns:
            bool: True if logged successfully
        """
        try:
            ip_address = self._get_client_ip()
            user_agent = self._get_user_agent()
            
            conn = sqlite3.connect(self.database_path)
            
            conn.execute('''
                INSERT INTO security_events 
                (event_type, user_id, username, description, ip_address, user_agent, 
                 severity, additional_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (event_type, user_id, username, description, ip_address, user_agent,
                  severity, json.dumps(additional_data) if additional_data else None))
            
            conn.commit()
            conn.close()
            
            audit_logger.log(
                getattr(logging, severity.upper()),
                f"SECURITY: {event_type} - {description} - User: {username}"
            )
            
            return True
            
        except Exception as e:
            audit_logger.error(f"Failed to log security event: {e}")
            return False
    
    def log_login_attempt(self, username: str, email: str, success: bool,
                         failure_reason: str = None) -> bool:
        """
        Log login attempts for authentication monitoring.
        
        Args:
            username: Username attempting login
            email: Email attempting login
            success: Whether login was successful
            failure_reason: Reason for failure if applicable
            
        Returns:
            bool: True if logged successfully
        """
        try:
            ip_address = self._get_client_ip()
            user_agent = self._get_user_agent()
            
            conn = sqlite3.connect(self.database_path)
            
            conn.execute('''
                INSERT INTO login_attempts 
                (username, email, ip_address, user_agent, success, failure_reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, email, ip_address, user_agent, success, failure_reason))
            
            conn.commit()
            conn.close()
            
            status = "SUCCESS" if success else "FAILED"
            audit_logger.info(f"LOGIN {status}: {username} ({email}) from {ip_address}")
            
            return True
            
        except Exception as e:
            audit_logger.error(f"Failed to log login attempt: {e}")
            return False
    
    def get_audit_logs(self, limit: int = 100, offset: int = 0,
                      user_id: Optional[int] = None, action_category: Optional[str] = None,
                      start_date: Optional[str] = None, end_date: Optional[str] = None,
                      risk_level: Optional[str] = None) -> Dict[str, Any]:
        """
        Retrieve audit logs with filtering and pagination.
        
        Args:
            limit: Maximum number of records to return
            offset: Number of records to skip
            user_id: Filter by user ID
            action_category: Filter by action category
            start_date: Start date for filtering (YYYY-MM-DD)
            end_date: End date for filtering (YYYY-MM-DD)
            risk_level: Filter by risk level
            
        Returns:
            Dict containing logs and metadata
        """
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            
            query = '''
                SELECT * FROM enhanced_audit_log 
                WHERE 1=1
            '''
            params = []
            
            if user_id:
                query += ' AND user_id = ?'
                params.append(user_id)
            
            if action_category:
                query += ' AND action_category = ?'
                params.append(action_category)
            
            if start_date:
                query += ' AND date(timestamp) >= ?'
                params.append(start_date)
            
            if end_date:
                query += ' AND date(timestamp) <= ?'
                params.append(end_date)
            
            if risk_level:
                query += ' AND risk_level = ?'
                params.append(risk_level)
            
            # Get total count
            count_query = query.replace('SELECT * FROM', 'SELECT COUNT(*) FROM')
            total_count = conn.execute(count_query, params).fetchone()[0]
            
            # Add ordering and pagination
            query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            
            logs = conn.execute(query, params).fetchall()
            conn.close()
            
            return {
                'logs': [dict(log) for log in logs],
                'total_count': total_count,
                'limit': limit,
                'offset': offset
            }
            
        except Exception as e:
            audit_logger.error(f"Failed to retrieve audit logs: {e}")
            return {'logs': [], 'total_count': 0, 'limit': limit, 'offset': offset}
    
    def get_security_events(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict]:
        """Get security events for monitoring dashboard"""
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            
            query = 'SELECT * FROM security_events'
            params = []
            
            if severity:
                query += ' WHERE severity = ?'
                params.append(severity)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            events = conn.execute(query, params).fetchall()
            conn.close()
            
            return [dict(event) for event in events]
            
        except Exception as e:
            audit_logger.error(f"Failed to retrieve security events: {e}")
            return []
    
    def get_login_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get login statistics for dashboard"""
        try:
            conn = sqlite3.connect(self.database_path)
            
            # Calculate date range
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            # Total login attempts
            total_attempts = conn.execute(
                'SELECT COUNT(*) FROM login_attempts WHERE date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            # Successful logins
            successful_logins = conn.execute(
                'SELECT COUNT(*) FROM login_attempts WHERE success = 1 AND date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            # Failed logins
            failed_logins = total_attempts - successful_logins
            
            # Unique users
            unique_users = conn.execute(
                'SELECT COUNT(DISTINCT email) FROM login_attempts WHERE success = 1 AND date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            # Recent failed attempts (potential attacks)
            recent_failures = conn.execute(
                '''SELECT email, ip_address, COUNT(*) as attempt_count 
                   FROM login_attempts 
                   WHERE success = 0 AND datetime(timestamp) > datetime('now', '-1 hour')
                   GROUP BY email, ip_address 
                   HAVING attempt_count > 3
                   ORDER BY attempt_count DESC''',
            ).fetchall()
            
            conn.close()
            
            return {
                'total_attempts': total_attempts,
                'successful_logins': successful_logins,
                'failed_logins': failed_logins,
                'success_rate': (successful_logins / total_attempts * 100) if total_attempts > 0 else 0,
                'unique_users': unique_users,
                'recent_suspicious_activity': [dict(zip(['email', 'ip_address', 'attempt_count'], row)) for row in recent_failures]
            }
            
        except Exception as e:
            audit_logger.error(f"Failed to get login statistics: {e}")
            return {}
    
    def get_audit_summary(self, days: int = 30) -> Dict[str, Any]:
        """Get audit summary for dashboard"""
        try:
            conn = sqlite3.connect(self.database_path)
            
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            # Total actions
            total_actions = conn.execute(
                'SELECT COUNT(*) FROM enhanced_audit_log WHERE date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            # Actions by category
            actions_by_category = conn.execute(
                '''SELECT action_category, COUNT(*) as count 
                   FROM enhanced_audit_log 
                   WHERE date(timestamp) >= ?
                   GROUP BY action_category 
                   ORDER BY count DESC''',
                (start_date,)
            ).fetchall()
            
            # High risk actions
            high_risk_actions = conn.execute(
                'SELECT COUNT(*) FROM enhanced_audit_log WHERE risk_level IN ("high", "critical") AND date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            # Failed actions
            failed_actions = conn.execute(
                'SELECT COUNT(*) FROM enhanced_audit_log WHERE success = 0 AND date(timestamp) >= ?',
                (start_date,)
            ).fetchone()[0]
            
            conn.close()
            
            return {
                'total_actions': total_actions,
                'actions_by_category': dict(actions_by_category),
                'high_risk_actions': high_risk_actions,
                'failed_actions': failed_actions
            }
            
        except Exception as e:
            audit_logger.error(f"Failed to get audit summary: {e}")
            return {}
    
    def _get_client_ip(self) -> str:
        """Get client IP address"""
        try:
            return request.environ.get('HTTP_X_FORWARDED_FOR', 
                                     request.environ.get('REMOTE_ADDR', 'unknown'))
        except:
            return 'unknown'
    
    def _get_user_agent(self) -> str:
        """Get user agent"""
        try:
            return request.environ.get('HTTP_USER_AGENT', 'unknown')
        except:
            return 'unknown'
    
    def _get_session_id(self) -> str:
        """Get session ID from cookies"""
        try:
            return request.cookies.get('rbac_session', 'no_session')
        except:
            return 'no_session'

# Example usage and testing
if __name__ == "__main__":
    print("🛡️ Audit Trail Manager - Demonstration")
    print("=" * 55)
    
    # Initialize audit manager
    audit_manager = AuditTrailManager("rbac_system.db")
    
    print("\n1. Testing Audit Logging:")
    
    # Test user action logging
    audit_manager.log_user_action(
        user_id=1, username="admin", user_role="admin",
        action_category="user_mgmt", action_type="create_user",
        action_details="Created new employee user",
        target_resource_type="user", target_resource_id="5",
        new_values={"email": "newuser@company.com", "role": "employee"},
        risk_level="low"
    )
    
    # Test security event logging
    audit_manager.log_security_event(
        event_type="suspicious_activity",
        user_id=None, username="unknown",
        description="Multiple failed login attempts detected",
        severity="warning",
        additional_data={"attempts": 5, "timeframe": "5 minutes"}
    )
    
    # Test login attempt logging
    audit_manager.log_login_attempt(
        username="testuser", email="test@company.com",
        success=False, failure_reason="Invalid password"
    )
    
    print("✅ Audit events logged successfully")
    
    print("\n2. Retrieving Audit Logs:")
    logs_result = audit_manager.get_audit_logs(limit=5)
    print(f"📊 Retrieved {len(logs_result['logs'])} audit logs")
    
    print("\n3. Login Statistics:")
    login_stats = audit_manager.get_login_statistics()
    for key, value in login_stats.items():
        if key != 'recent_suspicious_activity':
            print(f"   {key}: {value}")
    
    print("\n4. Audit Summary:")
    audit_summary = audit_manager.get_audit_summary()
    for key, value in audit_summary.items():
        print(f"   {key}: {value}")
    
    print("\n" + "=" * 55)
    print("📋 Comprehensive audit trail system demonstrated!")
    print("🔍 All user actions, security events, and login attempts tracked!")
