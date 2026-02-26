"""
SQL Injection Prevention Module for RBAC System

This module demonstrates secure database query handling using parameterized queries
and input validation to prevent SQL injection attacks in Flask applications.

Key Security Features:
1. Parameterized queries using ? placeholders
2. Input validation and sanitization
3. ORM-like helper functions
4. Secure query patterns
5. Protection against common SQL injection vectors
"""

import sqlite3
import re
import html
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
import logging

# Configure logging for security events
logging.basicConfig(level=logging.INFO)
security_logger = logging.getLogger('sql_security')

class SQLInjectionPrevention:
    """
    A comprehensive class for preventing SQL injection attacks in Flask applications.
    """
    
    def __init__(self, database_path: str):
        """
        Initialize the SQL injection prevention helper.
        
        Args:
            database_path (str): Path to the SQLite database
        """
        self.database_path = database_path
        self.dangerous_patterns = [
            r"(;|--|/\*|\*/|\\|\|\||&&)",
            r"\b(union|select|insert|delete|update|drop|create|alter|exec|execute)\b",
            r"<\s*(script|iframe|object|embed|form)",
            r"\b(xp_|sp_|cmdshell|openrowset|openquery)\b"
        ]
    
    def validate_input(self, input_value: Any, field_name: str) -> bool:
        """
        Validate input for potential SQL injection patterns.
        
        Args:
            input_value: The input value to validate
            field_name: Name of the field being validated
            
        Returns:
            bool: True if input is safe, False otherwise
        """
        if input_value is None:
            return True
            
        input_str = str(input_value).lower()
        
        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, input_str, re.IGNORECASE):
                security_logger.warning(f"Potential SQL injection detected in {field_name}: {input_value}")
                return False
        
        return True
    
    def sanitize_input(self, input_value: Any) -> str:
        """
        Sanitize input by escaping HTML and removing dangerous characters.
        
        Args:
            input_value: The input to sanitize
            
        Returns:
            str: Sanitized input
        """
        if input_value is None:
            return ""
        
        # Convert to string and escape HTML
        sanitized = html.escape(str(input_value))
        
        # Remove null bytes and other dangerous characters
        sanitized = sanitized.replace('\x00', '')
        
        return sanitized.strip()
    
    def get_secure_connection(self) -> sqlite3.Connection:
        """
        Get a secure database connection with proper configuration.
        
        Returns:
            sqlite3.Connection: Configured database connection
        """
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        
        # Enable foreign key constraints
        conn.execute("PRAGMA foreign_keys = ON")
        
        # Set secure journal mode
        conn.execute("PRAGMA journal_mode = WAL")
        
        return conn
    
    def execute_secure_query(self, query: str, params: Tuple = (), 
                           fetch_one: bool = False) -> Union[List[sqlite3.Row], sqlite3.Row, None]:
        """
        Execute a parameterized query securely.
        
        Args:
            query: SQL query with ? placeholders
            params: Parameters for the query
            fetch_one: Whether to fetch only one result
            
        Returns:
            Query results or None
        """
        try:
            # Validate query structure
            if not self._is_query_safe(query):
                security_logger.error(f"Unsafe query detected: {query}")
                return None
            
            conn = self.get_secure_connection()
            cursor = conn.execute(query, params)
            
            if fetch_one:
                result = cursor.fetchone()
            else:
                result = cursor.fetchall()
            
            conn.commit()
            conn.close()
            
            return result
            
        except sqlite3.Error as e:
            security_logger.error(f"Database error: {e}")
            return None
    
    def _is_query_safe(self, query: str) -> bool:
        """
        Check if a query is safe (uses parameterized queries).
        
        Args:
            query: SQL query to check
            
        Returns:
            bool: True if query is safe
        """
        query_lower = query.lower()
        
        # Check for parameterized queries (should use ? placeholders)
        if "?" not in query and any(keyword in query_lower for keyword in ['where', 'values', 'set']):
            return False
        
        # Check for dangerous SQL keywords in unsafe contexts
        dangerous_keywords = ['union', 'drop', 'alter', 'exec', 'execute', 'sp_', 'xp_']
        for keyword in dangerous_keywords:
            if keyword in query_lower:
                return False
        
        return True

class SecureUserRepository:
    """
    A secure repository class for user-related database operations.
    Demonstrates ORM-like patterns for secure database access.
    """
    
    def __init__(self, database_path: str):
        """
        Initialize the secure user repository.
        
        Args:
            database_path: Path to the SQLite database
        """
        self.sql_guard = SQLInjectionPrevention(database_path)
    
    def find_user_by_email(self, email: str) -> Optional[Dict]:
        """
        Securely find a user by email address.
        
        Args:
            email: User's email address
            
        Returns:
            User data dictionary or None
        """
        # Validate input
        if not self.sql_guard.validate_input(email, "email"):
            return None
        
        # Sanitize input
        email = self.sql_guard.sanitize_input(email)
        
        # Use parameterized query
        query = """
            SELECT id, first_name, last_name, email, role, department, status, created_at
            FROM users 
            WHERE email = ? AND status = 'active'
        """
        
        result = self.sql_guard.execute_secure_query(query, (email,), fetch_one=True)
        
        if result:
            return {
                'id': result['id'],
                'firstName': result['first_name'],
                'lastName': result['last_name'],
                'email': result['email'],
                'role': result['role'],
                'department': result['department'],
                'status': result['status'],
                'createdAt': result['created_at']
            }
        
        return None
    
    def authenticate_user(self, email: str, password_hash: str) -> Optional[Dict]:
        """
        Securely authenticate a user.
        
        Args:
            email: User's email address
            password_hash: Hashed password
            
        Returns:
            User data dictionary or None
        """
        # Validate inputs
        if not self.sql_guard.validate_input(email, "email"):
            return None
        if not self.sql_guard.validate_input(password_hash, "password"):
            return None
        
        # Sanitize inputs
        email = self.sql_guard.sanitize_input(email)
        password_hash = self.sql_guard.sanitize_input(password_hash)
        
        # Use parameterized query
        query = """
            SELECT id, first_name, last_name, email, role, department, status
            FROM users 
            WHERE email = ? AND password = ? AND status = 'active'
        """
        
        result = self.sql_guard.execute_secure_query(query, (email, password_hash), fetch_one=True)
        
        if result:
            return {
                'id': result['id'],
                'firstName': result['first_name'],
                'lastName': result['last_name'],
                'email': result['email'],
                'role': result['role'],
                'department': result['department'],
                'status': result['status']
            }
        
        return None
    
    def create_user(self, user_data: Dict) -> Optional[int]:
        """
        Securely create a new user.
        
        Args:
            user_data: Dictionary containing user information
            
        Returns:
            New user ID or None
        """
        # Validate all inputs
        required_fields = ['firstName', 'lastName', 'email', 'password', 'role', 'department']
        for field in required_fields:
            if field not in user_data:
                return None
            if not self.sql_guard.validate_input(user_data[field], field):
                return None
        
        # Sanitize inputs
        sanitized_data = {
            'firstName': self.sql_guard.sanitize_input(user_data['firstName']),
            'lastName': self.sql_guard.sanitize_input(user_data['lastName']),
            'email': self.sql_guard.sanitize_input(user_data['email']),
            'password': user_data['password'],  # Already hashed
            'role': self.sql_guard.sanitize_input(user_data['role']),
            'department': self.sql_guard.sanitize_input(user_data['department'])
        }
        
        # Use parameterized query
        query = """
            INSERT INTO users (first_name, last_name, email, password, role, department)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        
        try:
            conn = self.sql_guard.get_secure_connection()
            cursor = conn.execute(query, (
                sanitized_data['firstName'],
                sanitized_data['lastName'],
                sanitized_data['email'],
                sanitized_data['password'],
                sanitized_data['role'],
                sanitized_data['department']
            ))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            return user_id
            
        except sqlite3.Error as e:
            security_logger.error(f"Error creating user: {e}")
            return None
    
    def update_user(self, user_id: int, user_data: Dict) -> bool:
        """
        Securely update user information.
        
        Args:
            user_id: ID of the user to update
            user_data: Dictionary containing updated user information
            
        Returns:
            True if successful, False otherwise
        """
        # Validate user ID
        if not isinstance(user_id, int) or user_id <= 0:
            return False
        
        # Validate inputs
        allowed_fields = ['firstName', 'lastName', 'email', 'role', 'status']
        update_fields = []
        update_values = []
        
        for field in allowed_fields:
            if field in user_data:
                if not self.sql_guard.validate_input(user_data[field], field):
                    return False
                
                # Map frontend field names to database column names
                db_field = {
                    'firstName': 'first_name',
                    'lastName': 'last_name',
                    'email': 'email',
                    'role': 'role',
                    'status': 'status'
                }.get(field, field)
                
                update_fields.append(f"{db_field} = ?")
                update_values.append(self.sql_guard.sanitize_input(user_data[field]))
        
        if not update_fields:
            return False
        
        # Add updated timestamp
        update_fields.append("updated_at = CURRENT_TIMESTAMP")
        update_values.append(user_id)
        
        # Use parameterized query
        query = f"""
            UPDATE users 
            SET {', '.join(update_fields)}
            WHERE id = ?
        """
        
        try:
            conn = self.sql_guard.get_secure_connection()
            conn.execute(query, update_values)
            conn.commit()
            conn.close()
            
            return True
            
        except sqlite3.Error as e:
            security_logger.error(f"Error updating user: {e}")
            return False
    
    def get_users_with_pagination(self, page: int = 1, per_page: int = 10, 
                                 role_filter: Optional[str] = None) -> Dict:
        """
        Securely get users with pagination and optional filtering.
        
        Args:
            page: Page number
            per_page: Number of users per page
            role_filter: Optional role filter
            
        Returns:
            Dictionary with users and pagination info
        """
        # Validate inputs
        if not isinstance(page, int) or page < 1:
            page = 1
        if not isinstance(per_page, int) or per_page < 1 or per_page > 100:
            per_page = 10
        
        offset = (page - 1) * per_page
        
        # Build query with optional role filter
        base_query = """
            SELECT id, first_name, last_name, email, role, department, status, created_at
            FROM users
        """
        
        params = []
        if role_filter:
            if not self.sql_guard.validate_input(role_filter, "role"):
                return {'users': [], 'total': 0, 'page': page, 'per_page': per_page}
            
            base_query += " WHERE role = ?"
            params.append(self.sql_guard.sanitize_input(role_filter))
        
        # Add pagination
        query = base_query + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        # Get total count
        count_query = "SELECT COUNT(*) as total FROM users"
        if role_filter:
            count_query += " WHERE role = ?"
            count_result = self.sql_guard.execute_secure_query(count_query, (role_filter,), fetch_one=True)
        else:
            count_result = self.sql_guard.execute_secure_query(count_query, (), fetch_one=True)
        
        total = count_result['total'] if count_result else 0
        
        # Get users
        users_result = self.sql_guard.execute_secure_query(query, params)
        
        users = []
        if users_result:
            for user in users_result:
                users.append({
                    'id': user['id'],
                    'firstName': user['first_name'],
                    'lastName': user['last_name'],
                    'email': user['email'],
                    'role': user['role'],
                    'department': user['department'],
                    'status': user['status'],
                    'createdAt': user['created_at']
                })
        
        return {
            'users': users,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': (total + per_page - 1) // per_page
        }

# Example usage and demonstration
if __name__ == "__main__":
    # Demonstrate secure database operations
    print("🛡️  SQL Injection Prevention - Security Demonstration")
    print("=" * 60)
    
    # Create security helper
    db_path = "rbac_system.db"
    security_helper = SQLInjectionPrevention(db_path)
    user_repo = SecureUserRepository(db_path)
    
    # Test input validation
    print("\n1. Testing Input Validation:")
    test_inputs = [
        ("valid@email.com", "Valid email"),
        ("test'; DROP TABLE users; --", "SQL Injection attempt"),
        ("admin'/**/OR/**/1=1", "SQL Injection with comments"),
        ("<script>alert('xss')</script>", "XSS attempt"),
        ("UNION SELECT * FROM users", "Union-based injection")
    ]
    
    for test_input, description in test_inputs:
        is_safe = security_helper.validate_input(test_input, "email")
        status = "✅ SAFE" if is_safe else "❌ DANGEROUS"
        print(f"   {status}: {description}")
    
    print("\n2. Secure Query Examples:")
    print("   ✅ SELECT * FROM users WHERE email = ?")
    print("   ✅ INSERT INTO users (name, email) VALUES (?, ?)")
    print("   ✅ UPDATE users SET name = ? WHERE id = ?")
    print("   ❌ SELECT * FROM users WHERE email = '" + "user_input" + "'")
    
    print("\n3. ORM-like Secure Operations:")
    print("   ✅ user_repo.find_user_by_email('user@example.com')")
    print("   ✅ user_repo.create_user(validated_data)")
    print("   ✅ user_repo.update_user(user_id, validated_data)")
    
    print("\n" + "=" * 60)
    print("🔒 All database operations use parameterized queries!")
    print("🛡️  Input validation prevents malicious data!")
    print("📊 Logging captures security events!")
