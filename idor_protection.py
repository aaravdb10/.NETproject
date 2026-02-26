"""
IDOR Protection Module for RBAC System

This module implements comprehensive protection against Insecure Direct Object References (IDOR)
including authorization checks, resource ownership validation, and secure access control.

Key Security Features:
1. Role-based authorization checks
2. Resource ownership validation
3. Session-based access control
4. Audit logging for access attempts
5. Secure parameter validation
"""

import sqlite3
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from flask import request, jsonify

# Configure logging for IDOR security
idor_logger = logging.getLogger('idor_security')
idor_logger.setLevel(logging.INFO)

class IDORProtectionManager:
    """
    Comprehensive IDOR protection manager that handles:
    - Resource ownership validation
    - Role-based access control
    - Authorization policy enforcement
    - Security audit logging
    """
    
    def __init__(self, database_path: str):
        """
        Initialize IDOR protection manager.
        
        Args:
            database_path: Path to SQLite database
        """
        self.database_path = database_path
        self._init_idor_tables()
    
    def _init_idor_tables(self):
        """Initialize IDOR-related database tables"""
        conn = sqlite3.connect(self.database_path)
        
        # Create access control log table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS idor_access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                target_resource_type TEXT NOT NULL,
                target_resource_id TEXT NOT NULL,
                action TEXT NOT NULL,
                access_granted BOOLEAN NOT NULL,
                denial_reason TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT DEFAULT 'low'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def validate_user_access(self, current_user: Dict[str, Any], target_user_id: int, 
                           action: str, ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """
        Validate if current user can access/modify target user.
        
        Args:
            current_user: Current authenticated user data
            target_user_id: ID of target user to access
            action: Action being performed (read, update, delete)
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Dict with access_granted boolean and reason
        """
        result = {
            'access_granted': False,
            'reason': 'Access denied',
            'risk_level': 'low'
        }
        
        try:
            current_user_id = current_user.get('user_id') or current_user.get('id')
            current_role = current_user.get('role')
            
            if not current_user_id or not current_role:
                result['reason'] = 'Invalid session data'
                result['risk_level'] = 'medium'
                self._log_idor_attempt(
                    None, 'user', target_user_id, action, False, 
                    'Invalid session data', ip_address, user_agent, 'medium'
                )
                return result
            
            # Check if target user exists
            target_user = self._get_user_by_id(target_user_id)
            if not target_user:
                result['reason'] = 'Target user not found'
                self._log_idor_attempt(
                    current_user_id, 'user', target_user_id, action, False,
                    'Target user not found', ip_address, user_agent
                )
                return result
            
            # Role-based authorization rules
            access_rules = self._get_access_rules(current_role, action)
            
            # Check ownership (users can access their own data)
            is_owner = current_user_id == target_user_id
            
            # Check role permissions
            can_access_others = access_rules['can_access_others']
            can_modify_others = access_rules['can_modify_others']
            can_delete_others = access_rules['can_delete_others']
            
            # Apply authorization logic
            if action == 'read':
                if is_owner or can_access_others:
                    result['access_granted'] = True
                    result['reason'] = 'Read access granted'
                else:
                    result['reason'] = 'Insufficient permissions for read access'
            
            elif action == 'update':
                if is_owner or can_modify_others:
                    # Additional checks for sensitive updates
                    if not is_owner and current_role != 'admin':
                        # Non-admins cannot modify others
                        result['reason'] = 'Only admins can modify other users'
                    else:
                        result['access_granted'] = True
                        result['reason'] = 'Update access granted'
                else:
                    result['reason'] = 'Insufficient permissions for update access'
            
            elif action == 'delete':
                if current_role == 'admin' and can_delete_others:
                    if is_owner:
                        # Prevent self-deletion
                        result['reason'] = 'Cannot delete own account'
                        result['risk_level'] = 'medium'
                    else:
                        result['access_granted'] = True
                        result['reason'] = 'Delete access granted'
                else:
                    result['reason'] = 'Insufficient permissions for delete access'
                    result['risk_level'] = 'medium'
            
            else:
                result['reason'] = f'Unknown action: {action}'
                result['risk_level'] = 'medium'
            
            # Log the access attempt
            self._log_idor_attempt(
                current_user_id, 'user', target_user_id, action,
                result['access_granted'], result['reason'],
                ip_address, user_agent, result['risk_level']
            )
            
            return result
            
        except Exception as e:
            idor_logger.error(f"Error validating user access: {e}")
            result['reason'] = 'Access validation error'
            result['risk_level'] = 'high'
            return result
    
    def validate_resource_access(self, current_user: Dict[str, Any], resource_type: str,
                               resource_id: str, action: str, 
                               ip_address: str = None, user_agent: str = None) -> Dict[str, Any]:
        """
        Generic resource access validation for any resource type.
        
        Args:
            current_user: Current authenticated user data
            resource_type: Type of resource (user, document, etc.)
            resource_id: ID of resource to access
            action: Action being performed
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Dict with access_granted boolean and reason
        """
        result = {
            'access_granted': False,
            'reason': 'Access denied',
            'risk_level': 'low'
        }
        
        try:
            current_user_id = current_user.get('user_id') or current_user.get('id')
            current_role = current_user.get('role')
            
            if not current_user_id or not current_role:
                result['reason'] = 'Invalid session data'
                result['risk_level'] = 'medium'
                return result
            
            # Resource-specific validation
            if resource_type == 'user':
                return self.validate_user_access(
                    current_user, int(resource_id), action, ip_address, user_agent
                )
            
            # Add more resource types as needed
            elif resource_type == 'audit_log':
                # Only admins can access audit logs
                if current_role == 'admin':
                    result['access_granted'] = True
                    result['reason'] = 'Admin access to audit logs'
                else:
                    result['reason'] = 'Only admins can access audit logs'
                    result['risk_level'] = 'medium'
            
            elif resource_type == 'session':
                # Users can only access their own sessions
                session_user_id = self._get_session_user_id(resource_id)
                if session_user_id == current_user_id or current_role == 'admin':
                    result['access_granted'] = True
                    result['reason'] = 'Session access granted'
                else:
                    result['reason'] = 'Can only access own sessions'
                    result['risk_level'] = 'high'
            
            else:
                result['reason'] = f'Unknown resource type: {resource_type}'
                result['risk_level'] = 'medium'
            
            # Log the access attempt
            self._log_idor_attempt(
                current_user_id, resource_type, resource_id, action,
                result['access_granted'], result['reason'],
                ip_address, user_agent, result['risk_level']
            )
            
            return result
            
        except Exception as e:
            idor_logger.error(f"Error validating resource access: {e}")
            result['reason'] = 'Resource validation error'
            result['risk_level'] = 'high'
            return result
    
    def _get_access_rules(self, role: str, action: str) -> Dict[str, bool]:
        """
        Get role-based access rules.
        
        Args:
            role: User role
            action: Action being performed
            
        Returns:
            Dict with permission flags
        """
        # Define role-based permissions
        permissions = {
            'admin': {
                'can_access_others': True,
                'can_modify_others': True,
                'can_delete_others': True,
                'can_create_users': True,
                'can_access_audit': True
            },
            'manager': {
                'can_access_others': True,
                'can_modify_others': False,
                'can_delete_others': False,
                'can_create_users': False,
                'can_access_audit': False
            },
            'employee': {
                'can_access_others': False,
                'can_modify_others': False,
                'can_delete_others': False,
                'can_create_users': False,
                'can_access_audit': False
            }
        }
        
        return permissions.get(role, permissions['employee'])
    
    def _get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user data by ID"""
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            
            user = conn.execute(
                'SELECT id, email, role, status FROM users WHERE id = ?',
                (user_id,)
            ).fetchone()
            
            conn.close()
            
            if user:
                return dict(user)
            return None
            
        except Exception as e:
            idor_logger.error(f"Error getting user by ID: {e}")
            return None
    
    def _get_session_user_id(self, session_token: str) -> Optional[int]:
        """Get user ID associated with session token"""
        try:
            conn = sqlite3.connect(self.database_path)
            
            result = conn.execute(
                'SELECT user_id FROM user_sessions WHERE session_token = ? AND is_active = TRUE',
                (session_token,)
            ).fetchone()
            
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            idor_logger.error(f"Error getting session user ID: {e}")
            return None
    
    def _log_idor_attempt(self, user_id: Optional[int], resource_type: str, 
                         resource_id: str, action: str, access_granted: bool,
                         reason: str, ip_address: str = None, 
                         user_agent: str = None, risk_level: str = 'low'):
        """Log IDOR access attempt"""
        try:
            conn = sqlite3.connect(self.database_path)
            
            conn.execute('''
                INSERT INTO idor_access_log 
                (user_id, target_resource_type, target_resource_id, action, 
                 access_granted, denial_reason, ip_address, user_agent, risk_level)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, resource_type, resource_id, action, access_granted,
                  reason, ip_address, user_agent, risk_level))
            
            conn.commit()
            conn.close()
            
            # Log to application logger
            log_level = 'INFO' if access_granted else 'WARNING'
            idor_logger.log(
                getattr(logging, log_level),
                f"IDOR {action} attempt: User {user_id} -> {resource_type}:{resource_id} - {reason}"
            )
            
        except Exception as e:
            idor_logger.error(f"Error logging IDOR attempt: {e}")
    
    def get_access_violations(self, user_id: Optional[int] = None, 
                            risk_level: Optional[str] = None,
                            limit: int = 100) -> List[Dict]:
        """
        Get IDOR access violations for monitoring.
        
        Args:
            user_id: Filter by user ID
            risk_level: Filter by risk level
            limit: Maximum number of records
            
        Returns:
            List of access violation records
        """
        try:
            conn = sqlite3.connect(self.database_path)
            conn.row_factory = sqlite3.Row
            
            query = '''
                SELECT * FROM idor_access_log 
                WHERE access_granted = FALSE
            '''
            params = []
            
            if user_id:
                query += ' AND user_id = ?'
                params.append(user_id)
            
            if risk_level:
                query += ' AND risk_level = ?'
                params.append(risk_level)
            
            query += ' ORDER BY timestamp DESC LIMIT ?'
            params.append(limit)
            
            violations = conn.execute(query, params).fetchall()
            conn.close()
            
            return [dict(violation) for violation in violations]
            
        except Exception as e:
            idor_logger.error(f"Error getting access violations: {e}")
            return []
    
    def get_access_statistics(self) -> Dict[str, Any]:
        """Get IDOR access statistics for monitoring"""
        try:
            conn = sqlite3.connect(self.database_path)
            
            # Total access attempts
            total_attempts = conn.execute(
                'SELECT COUNT(*) FROM idor_access_log'
            ).fetchone()[0]
            
            # Denied attempts
            denied_attempts = conn.execute(
                'SELECT COUNT(*) FROM idor_access_log WHERE access_granted = FALSE'
            ).fetchone()[0]
            
            # High risk attempts
            high_risk_attempts = conn.execute(
                'SELECT COUNT(*) FROM idor_access_log WHERE risk_level = "high"'
            ).fetchone()[0]
            
            # Recent attempts (last 24 hours)
            recent_attempts = conn.execute(
                '''SELECT COUNT(*) FROM idor_access_log 
                   WHERE datetime(timestamp) > datetime('now', '-1 day')'''
            ).fetchone()[0]
            
            conn.close()
            
            return {
                'total_attempts': total_attempts,
                'denied_attempts': denied_attempts,
                'high_risk_attempts': high_risk_attempts,
                'recent_attempts': recent_attempts,
                'success_rate': ((total_attempts - denied_attempts) / total_attempts * 100) if total_attempts > 0 else 0
            }
            
        except Exception as e:
            idor_logger.error(f"Error getting access statistics: {e}")
            return {}

def require_authorization(resource_type: str = 'user', action: str = 'read'):
    """
    Decorator for endpoints that require IDOR protection.
    
    Args:
        resource_type: Type of resource being accessed
        action: Action being performed
        
    Returns:
        Decorator function
    """
    def decorator(f):
        def wrapper(*args, **kwargs):
            from flask import request, jsonify, g
            
            # Get session data (should be set by require_valid_session decorator)
            session_data = getattr(request, 'session_data', None)
            if not session_data:
                return jsonify({'success': False, 'message': 'Authentication required'}), 401
            
            # Extract resource ID from URL parameters
            resource_id = kwargs.get('user_id') or kwargs.get('resource_id')
            if not resource_id:
                return jsonify({'success': False, 'message': 'Resource ID required'}), 400
            
            # Get client info
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', 
                                           request.environ.get('REMOTE_ADDR', 'unknown'))
            user_agent = request.environ.get('HTTP_USER_AGENT', 'unknown')
            
            # Initialize IDOR protection
            from app import idor_manager
            
            # Validate access
            access_result = idor_manager.validate_resource_access(
                session_data, resource_type, str(resource_id), action,
                ip_address, user_agent
            )
            
            if not access_result['access_granted']:
                return jsonify({
                    'success': False, 
                    'message': 'Access denied',
                    'reason': access_result['reason']
                }), 403
            
            # Store authorization info for use in endpoint
            request.authorization_info = access_result
            
            return f(*args, **kwargs)
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

# Example usage and demonstration
if __name__ == "__main__":
    print("🛡️ IDOR Protection Manager - Demonstration")
    print("=" * 55)
    
    # Initialize IDOR protection
    idor_manager = IDORProtectionManager("rbac_system.db")
    
    print("\n1. Testing Role-Based Access Control:")
    
    # Simulate different user roles trying to access user ID 2
    test_users = [
        {'user_id': 1, 'role': 'admin', 'email': 'admin@company.com'},
        {'user_id': 2, 'role': 'employee', 'email': 'employee@company.com'},
        {'user_id': 3, 'role': 'manager', 'email': 'manager@company.com'}
    ]
    
    target_user_id = 2
    actions = ['read', 'update', 'delete']
    
    for user in test_users:
        print(f"\n   Testing {user['role']} (ID: {user['user_id']}) accessing User {target_user_id}:")
        for action in actions:
            result = idor_manager.validate_user_access(
                user, target_user_id, action, '192.168.1.100', 'Test-Agent'
            )
            status = "✅ GRANTED" if result['access_granted'] else "❌ DENIED"
            print(f"     {action.upper()}: {status} - {result['reason']}")
    
    print("\n2. Testing Self-Access (Owner Access):")
    
    # Test user accessing their own data
    self_access_result = idor_manager.validate_user_access(
        {'user_id': 2, 'role': 'employee'}, 2, 'update', '192.168.1.100', 'Test-Agent'
    )
    status = "✅ GRANTED" if self_access_result['access_granted'] else "❌ DENIED"
    print(f"   Employee accessing own data: {status} - {self_access_result['reason']}")
    
    print("\n3. Access Statistics:")
    stats = idor_manager.get_access_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n4. Recent Access Violations:")
    violations = idor_manager.get_access_violations(limit=5)
    if violations:
        for violation in violations[:3]:  # Show first 3
            print(f"   User {violation['user_id']} -> {violation['target_resource_type']}:{violation['target_resource_id']}")
            print(f"   Action: {violation['action']}, Reason: {violation['denial_reason']}")
    else:
        print("   No recent violations found")
    
    print("\n" + "=" * 55)
    print("🔒 IDOR protection features demonstrated!")
    print("🛡️ Authorization checks, ownership validation, and audit logging!")
