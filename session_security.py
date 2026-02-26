"""
Session Security Module for RBAC System

This module implements comprehensive session security including:
- Secure cookie configuration (HttpOnly, Secure, SameSite)
- Session hijacking protection
- Proper session lifecycle management
- Session token generation and validation
- Logout security measures
"""

import secrets
import hashlib
import time
import json
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import sqlite3
import logging

# Configure logging for session security
session_logger = logging.getLogger('session_security')
session_logger.setLevel(logging.INFO)

class SessionSecurityManager:
    """
    Comprehensive session security manager that handles:
    - Secure session token generation
    - Session storage and validation
    - Anti-hijacking measures
    - Secure logout procedures
    """
    
    def __init__(self, database_path: str, session_timeout: int = 3600):
        """
        Initialize session security manager.
        
        Args:
            database_path: Path to SQLite database
            session_timeout: Session timeout in seconds (default: 1 hour)
        """
        self.database_path = database_path
        self.session_timeout = session_timeout
        self._init_session_tables()
    
    def _init_session_tables(self):
        """Initialize session-related database tables"""
        conn = sqlite3.connect(self.database_path)
        
        # Create users table if it doesn't exist (for testing)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'employee',
                department TEXT,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create sessions table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                user_agent TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                logout_reason TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create session security log table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS session_security_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_token TEXT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                risk_level TEXT DEFAULT 'low'
            )
        ''')
        
        # Insert demo user for testing
        conn.execute('''
            INSERT OR IGNORE INTO users (id, first_name, last_name, email, password, role, status)
            VALUES (1, 'Test', 'User', 'test@example.com', 'hashed_password', 'admin', 'active')
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate cryptographically secure session token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            Hex-encoded secure token
        """
        return secrets.token_hex(length)
    
    def create_session(self, user_id: int, ip_address: str, user_agent: str) -> str:
        """
        Create a new secure session.
        
        Args:
            user_id: ID of the user
            ip_address: Client IP address
            user_agent: Client user agent string
            
        Returns:
            Session token
        """
        # Generate secure session token
        session_token = self.generate_secure_token()
        
        # Calculate expiration time
        expires_at = datetime.now() + timedelta(seconds=self.session_timeout)
        
        # Store session in database
        conn = sqlite3.connect(self.database_path)
        conn.execute('''
            INSERT INTO user_sessions 
            (session_token, user_id, user_agent, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_token, user_id, user_agent, ip_address, expires_at))
        
        conn.commit()
        conn.close()
        
        # Log session creation
        self._log_session_event(
            session_token, user_id, 'session_created', 
            ip_address, user_agent, 
            f'New session created for user {user_id}'
        )
        
        session_logger.info(f"Secure session created for user {user_id} from {ip_address}")
        
        return session_token
    
    def validate_session(self, session_token: str, ip_address: str, 
                        user_agent: str) -> Optional[Dict[str, Any]]:
        """
        Validate session token and check for security issues.
        
        Args:
            session_token: Session token to validate
            ip_address: Current client IP address
            user_agent: Current client user agent
            
        Returns:
            Session data if valid, None if invalid
        """
        if not session_token:
            return None
        
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        
        # Get session data
        session = conn.execute('''
            SELECT s.*, u.email, u.role, u.first_name, u.last_name, u.status
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.session_token = ? AND s.is_active = TRUE
        ''', (session_token,)).fetchone()
        
        conn.close()
        
        if not session:
            self._log_session_event(
                session_token, None, 'invalid_session',
                ip_address, user_agent, 'Invalid session token used'
            )
            return None
        
        # Check if session has expired
        expires_at = datetime.fromisoformat(session['expires_at'])
        if datetime.now() > expires_at:
            self._invalidate_session(session_token, 'expired')
            self._log_session_event(
                session_token, session['user_id'], 'session_expired',
                ip_address, user_agent, 'Session expired'
            )
            return None
        
        # Check for session hijacking indicators
        hijack_detected = self._detect_session_hijacking(session, ip_address, user_agent)
        if hijack_detected:
            self._invalidate_session(session_token, 'hijack_detected')
            self._log_session_event(
                session_token, session['user_id'], 'hijack_detected',
                ip_address, user_agent, 
                'Potential session hijacking detected', 'high'
            )
            session_logger.warning(f"Potential session hijacking detected for user {session['user_id']}")
            return None
        
        # Check if user account is still active
        if session['status'] != 'active':
            self._invalidate_session(session_token, 'user_inactive')
            return None
        
        # Update last activity
        self._update_session_activity(session_token)
        
        # Return session data
        return {
            'user_id': session['user_id'],
            'email': session['email'],
            'role': session['role'],
            'first_name': session['first_name'],
            'last_name': session['last_name'],
            'session_token': session_token,
            'created_at': session['created_at'],
            'last_activity': session['last_activity']
        }
    
    def _detect_session_hijacking(self, session: sqlite3.Row, 
                                current_ip: str, current_ua: str) -> bool:
        """
        Detect potential session hijacking based on various indicators.
        
        Args:
            session: Session record from database
            current_ip: Current request IP address
            current_ua: Current request user agent
            
        Returns:
            True if hijacking is detected
        """
        # Check IP address change (strict check - can be configured)
        if session['ip_address'] != current_ip:
            # Log IP change but don't immediately block (could be mobile/proxy)
            self._log_session_event(
                session['session_token'], session['user_id'], 'ip_change',
                current_ip, current_ua,
                f"IP changed from {session['ip_address']} to {current_ip}", 'medium'
            )
            # For demo purposes, we'll allow IP changes but log them
            # In production, you might want to require re-authentication
        
        # Check user agent change (major changes indicate potential hijacking)
        if session['user_agent'] and current_ua:
            if not self._user_agents_similar(session['user_agent'], current_ua):
                session_logger.warning(
                    f"User agent change detected for session {session['session_token']}"
                )
                return True
        
        # Check for rapid location changes (would require GeoIP)
        # This is a placeholder for more advanced detection
        
        return False
    
    def _user_agents_similar(self, original_ua: str, current_ua: str) -> bool:
        """
        Check if user agents are similar enough to be from the same client.
        
        Args:
            original_ua: Original user agent
            current_ua: Current user agent
            
        Returns:
            True if user agents are similar
        """
        if not original_ua or not current_ua:
            return True
        
        # Extract browser and OS information
        def extract_browser_os(ua):
            ua_lower = ua.lower()
            browser = 'unknown'
            os = 'unknown'
            
            # Detect browser
            if 'chrome' in ua_lower and 'edg' not in ua_lower:
                browser = 'chrome'
            elif 'firefox' in ua_lower:
                browser = 'firefox'
            elif 'safari' in ua_lower and 'chrome' not in ua_lower:
                browser = 'safari'
            elif 'edge' in ua_lower or 'edg' in ua_lower:
                browser = 'edge'
            
            # Detect OS
            if 'windows' in ua_lower:
                os = 'windows'
            elif 'mac' in ua_lower:
                os = 'macos'
            elif 'linux' in ua_lower:
                os = 'linux'
            elif 'android' in ua_lower:
                os = 'android'
            elif 'ios' in ua_lower:
                os = 'ios'
            
            return browser, os
        
        orig_browser, orig_os = extract_browser_os(original_ua)
        curr_browser, curr_os = extract_browser_os(current_ua)
        
        # Consider similar if browser and OS match
        return orig_browser == curr_browser and orig_os == curr_os
    
    def _update_session_activity(self, session_token: str):
        """Update session last activity timestamp"""
        conn = sqlite3.connect(self.database_path)
        conn.execute('''
            UPDATE user_sessions 
            SET last_activity = CURRENT_TIMESTAMP 
            WHERE session_token = ?
        ''', (session_token,))
        conn.commit()
        conn.close()
    
    def _invalidate_session(self, session_token: str, reason: str):
        """Invalidate a session"""
        conn = sqlite3.connect(self.database_path)
        conn.execute('''
            UPDATE user_sessions 
            SET is_active = FALSE, logout_reason = ?
            WHERE session_token = ?
        ''', (reason, session_token))
        conn.commit()
        conn.close()
    
    def logout_session(self, session_token: str, ip_address: str, 
                      user_agent: str, reason: str = 'user_logout') -> bool:
        """
        Securely logout a session.
        
        Args:
            session_token: Session token to logout
            ip_address: Client IP address
            user_agent: Client user agent
            reason: Logout reason
            
        Returns:
            True if logout successful
        """
        # Get session info before invalidating
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        session = conn.execute('''
            SELECT user_id FROM user_sessions 
            WHERE session_token = ? AND is_active = TRUE
        ''', (session_token,)).fetchone()
        conn.close()
        
        if not session:
            return False
        
        # Invalidate session
        self._invalidate_session(session_token, reason)
        
        # Log logout
        self._log_session_event(
            session_token, session['user_id'], 'logout',
            ip_address, user_agent, f'Session logged out: {reason}'
        )
        
        session_logger.info(f"Session {session_token} logged out: {reason}")
        
        return True
    
    def logout_all_user_sessions(self, user_id: int, reason: str = 'logout_all'):
        """
        Logout all sessions for a specific user.
        
        Args:
            user_id: User ID
            reason: Logout reason
        """
        conn = sqlite3.connect(self.database_path)
        conn.execute('''
            UPDATE user_sessions 
            SET is_active = FALSE, logout_reason = ?
            WHERE user_id = ? AND is_active = TRUE
        ''', (reason, user_id))
        
        affected_rows = conn.total_changes
        conn.commit()
        conn.close()
        
        self._log_session_event(
            None, user_id, 'logout_all',
            None, None, f'All sessions logged out for user {user_id}: {reason}'
        )
        
        session_logger.info(f"All sessions for user {user_id} logged out: {affected_rows} sessions")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions from database"""
        conn = sqlite3.connect(self.database_path)
        
        # Mark expired sessions as inactive
        cursor = conn.execute('''
            UPDATE user_sessions 
            SET is_active = FALSE, logout_reason = 'expired'
            WHERE expires_at < CURRENT_TIMESTAMP AND is_active = TRUE
        ''')
        
        expired_count = cursor.rowcount
        
        # Optionally delete old session records (older than 30 days)
        conn.execute('''
            DELETE FROM user_sessions 
            WHERE created_at < datetime('now', '-30 days')
        ''')
        
        conn.commit()
        conn.close()
        
        if expired_count > 0:
            session_logger.info(f"Cleaned up {expired_count} expired sessions")
    
    def get_user_sessions(self, user_id: int) -> list:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of active sessions
        """
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        
        sessions = conn.execute('''
            SELECT session_token, ip_address, user_agent, created_at, last_activity
            FROM user_sessions
            WHERE user_id = ? AND is_active = TRUE
            ORDER BY last_activity DESC
        ''', (user_id,)).fetchall()
        
        conn.close()
        
        return [dict(session) for session in sessions]
    
    def _log_session_event(self, session_token: Optional[str], user_id: Optional[int], 
                          event_type: str, ip_address: Optional[str], 
                          user_agent: Optional[str], details: str, 
                          risk_level: str = 'low'):
        """Log session security events"""
        conn = sqlite3.connect(self.database_path)
        conn.execute('''
            INSERT INTO session_security_log 
            (session_token, user_id, event_type, ip_address, user_agent, details, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_token, user_id, event_type, ip_address, user_agent, details, risk_level))
        conn.commit()
        conn.close()
    
    def get_security_events(self, user_id: Optional[int] = None, 
                           risk_level: Optional[str] = None, 
                           limit: int = 100) -> list:
        """
        Get session security events.
        
        Args:
            user_id: Filter by user ID
            risk_level: Filter by risk level
            limit: Maximum number of events to return
            
        Returns:
            List of security events
        """
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        
        query = "SELECT * FROM session_security_log WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if risk_level:
            query += " AND risk_level = ?"
            params.append(risk_level)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        events = conn.execute(query, params).fetchall()
        conn.close()
        
        return [dict(event) for event in events]

def get_secure_cookie_config():
    """
    Get secure cookie configuration for Flask.
    
    Returns:
        Dictionary with secure cookie settings
    """
    return {
        'SESSION_COOKIE_SECURE': True,  # Only send over HTTPS
        'SESSION_COOKIE_HTTPONLY': True,  # Prevent JavaScript access
        'SESSION_COOKIE_SAMESITE': 'Strict',  # CSRF protection
        'SESSION_COOKIE_NAME': 'rbac_session',  # Custom cookie name
        'PERMANENT_SESSION_LIFETIME': timedelta(hours=1),  # Session timeout
    }

# Example usage and testing
if __name__ == "__main__":
    print("🔐 Session Security Manager - Demonstration")
    print("=" * 55)
    
    # Initialize session manager
    session_manager = SessionSecurityManager("rbac_system.db")
    
    print("\n1. Creating secure session...")
    session_token = session_manager.create_session(
        user_id=1,
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    print(f"   Session Token: {session_token[:16]}...")
    
    print("\n2. Validating session...")
    session_data = session_manager.validate_session(
        session_token,
        "192.168.1.100",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    if session_data:
        print(f"   ✅ Valid session for user: {session_data['email']}")
    else:
        print("   ❌ Invalid session")
    
    print("\n3. Testing session hijacking detection...")
    hijack_result = session_manager.validate_session(
        session_token,
        "10.0.0.1",  # Different IP
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)"  # Different user agent
    )
    if hijack_result:
        print("   ⚠️  Session allowed despite changes")
    else:
        print("   ✅ Potential hijacking detected and blocked")
    
    print("\n4. Secure logout...")
    logout_success = session_manager.logout_session(
        session_token,
        "192.168.1.100",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    )
    print(f"   ✅ Logout successful: {logout_success}")
    
    print("\n5. Secure cookie configuration:")
    cookie_config = get_secure_cookie_config()
    for key, value in cookie_config.items():
        print(f"   {key}: {value}")
    
    print("\n" + "=" * 55)
    print("🛡️  Session security features demonstrated!")
    print("🔒 Secure cookies, hijacking protection, and proper logout!")
