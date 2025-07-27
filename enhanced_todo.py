import streamlit as st
from datetime import datetime, timedelta, date, time
import sqlite3
from sqlite3 import Error
import pytz
from typing import Optional, List, Tuple, Union, Dict
import uuid
import bcrypt
import logging
import os
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_validator import validate_email, EmailNotValidError
from password_validator import PasswordValidator
import secrets
import string
import random
import json
import urllib.parse
import requests
import streamlit.components.v1 as components

# --- SQLite datetime adapter/converter for Python 3.12+ compatibility ---
def adapt_datetime(val):
    return val.isoformat() if val else None

def convert_datetime(val):
    if val is None:
        return None
    try:
        return datetime.fromisoformat(val.decode() if isinstance(val, bytes) else val)
    except Exception:
        return None

sqlite3.register_adapter(datetime, adapt_datetime)
sqlite3.register_converter("timestamp", convert_datetime)
sqlite3.register_converter("TIMESTAMP", convert_datetime)
sqlite3.register_converter("DATETIME", convert_datetime)

# Setup logging
LOG_FILE = 'todo_error.log'
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, 
                    format='%(asctime)s %(levelname)s %(message)s')

def log_error(msg):
    logging.error(msg)

# Email Configuration
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': os.getenv('SENDER_EMAIL'),
    'sender_password': os.getenv('SENDER_PASSWORD')
}

# Google OAuth Configuration
GOOGLE_OAUTH_CONFIG = {
    'client_id': os.getenv('GOOGLE_CLIENT_ID', 'enter_your_client_id_here'),
    'client_secret': os.getenv('GOOGLE_CLIENT_SECRET', 'enter_your_client_secret_here'),
    'redirect_uri': os.getenv('GOOGLE_REDIRECT_URI', 'enter_your_redirect_uri_here'),
    'scope': 'openid email profile'
}

# Database Setup
DB_FILE = 'todo.db'

def create_connection():
    """Create a database connection to a SQLite database"""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
        return conn
    except Error as e:
        st.error(f"Database error: {e}")
        log_error(f"Database error: {e}")
    return conn

def initialize_database():
    """Initialize the database tables"""
    conn = create_connection()
    if conn is not None:
        try:
            c = conn.cursor()
            
            # Users table with enhanced authentication fields
            c.execute('''CREATE TABLE IF NOT EXISTS users
                         (id TEXT PRIMARY KEY, 
                          username TEXT UNIQUE, 
                          email TEXT UNIQUE,
                          password TEXT, 
                          email_verified BOOLEAN DEFAULT FALSE,
                          verification_token TEXT,
                          reset_token TEXT,
                          reset_token_expires TIMESTAMP,
                          google_id TEXT,
                          profile_picture TEXT,
                          created_at TIMESTAMP,
                          last_login TIMESTAMP)''')
            
            # OTP verification table
            c.execute('''CREATE TABLE IF NOT EXISTS otps
                         (id TEXT PRIMARY KEY,
                          email TEXT,
                          otp_code TEXT,
                          otp_type TEXT,
                          expires_at TIMESTAMP,
                          used BOOLEAN DEFAULT FALSE,
                          created_at TIMESTAMP)''')
            
            # Lists table
            c.execute('''CREATE TABLE IF NOT EXISTS lists
                         (id TEXT PRIMARY KEY, 
                          user_id TEXT, 
                          name TEXT, 
                          color TEXT, 
                          icon TEXT, 
                          created_at TIMESTAMP,
                          FOREIGN KEY (user_id) REFERENCES users (id))''')
            
            # Tasks table
            c.execute('''CREATE TABLE IF NOT EXISTS tasks
                         (id TEXT PRIMARY KEY, 
                          list_id TEXT, 
                          user_id TEXT, 
                          title TEXT, 
                          description TEXT, 
                          due_date TEXT, 
                          reminder TEXT, 
                          is_completed BOOLEAN, 
                          is_important BOOLEAN, 
                          created_at TIMESTAMP, 
                          updated_at TIMESTAMP,
                          completed_at TIMESTAMP,
                          recurrence_pattern TEXT,
                          FOREIGN KEY (list_id) REFERENCES lists (id),
                          FOREIGN KEY (user_id) REFERENCES users (id))''')
            
            # Subtasks table
            c.execute('''CREATE TABLE IF NOT EXISTS subtasks
                         (id TEXT PRIMARY KEY, 
                          task_id TEXT, 
                          title TEXT, 
                          is_completed BOOLEAN,
                          created_at TIMESTAMP,
                          FOREIGN KEY (task_id) REFERENCES tasks (id))''')
            
            conn.commit()
        except Error as e:
            st.error(f"Database initialization error: {e}")
            log_error(f"Database initialization error: {e}")
        finally:
            conn.close()

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def get_default_lists():
    return [
        ("My Day", "#0078d7", "sun"),
        ("Important", "#d83b01", "star"),
        ("Planned", "#107c10", "calendar"),
        ("Tasks", "#737373", "home")
    ]

class LivePasswordValidator:
    """Enhanced live password validation with real-time feedback"""
    
    def __init__(self):
        self.requirements = {
            'min_length': {'value': 8, 'description': 'At least 8 characters'},
            'uppercase': {'value': 1, 'description': 'At least 1 uppercase letter'},
            'lowercase': {'value': 1, 'description': 'At least 1 lowercase letter'},
            'digits': {'value': 1, 'description': 'At least 1 number'},
            'special': {'value': 1, 'description': 'At least 1 special character'},
        }
        
        self.weak_patterns = [
            'password', '123456', 'qwerty', 'abc123', 'admin', 'user', 
            'test', 'welcome', 'hello', 'letmein', '111111', 'password123'
        ]
    
    def validate_live(self, password: str) -> Dict[str, Union[bool, str, List[Dict], int]]:
        """Real-time password validation with detailed feedback"""
        if not password:
            return {
                'is_valid': False,
                'strength_score': 0,
                'strength_level': 'none',
                'requirements': [],
                'suggestions': ['Enter a password to see requirements'],
                'entropy': 0
            }
        
        requirements = []
        score = 0
        suggestions = []
        
        # Check length
        length_met = len(password) >= self.requirements['min_length']['value']
        requirements.append({
            'name': 'Length',
            'description': self.requirements['min_length']['description'],
            'met': length_met,
            'icon': '✅' if length_met else '❌'
        })
        if length_met:
            score += 2
        else:
            suggestions.append(f"Add {self.requirements['min_length']['value'] - len(password)} more characters")
        
        # Check uppercase
        uppercase_count = sum(1 for c in password if c.isupper())
        uppercase_met = uppercase_count >= self.requirements['uppercase']['value']
        requirements.append({
            'name': 'Uppercase',
            'description': self.requirements['uppercase']['description'],
            'met': uppercase_met,
            'icon': '✅' if uppercase_met else '❌'
        })
        if uppercase_met:
            score += 1
        else:
            suggestions.append("Add uppercase letters (A-Z)")
        
        # Check lowercase
        lowercase_count = sum(1 for c in password if c.islower())
        lowercase_met = lowercase_count >= self.requirements['lowercase']['value']
        requirements.append({
            'name': 'Lowercase',
            'description': self.requirements['lowercase']['description'],
            'met': lowercase_met,
            'icon': '✅' if lowercase_met else '❌'
        })
        if lowercase_met:
            score += 1
        else:
            suggestions.append("Add lowercase letters (a-z)")
        
        # Check digits
        digits_count = sum(1 for c in password if c.isdigit())
        digits_met = digits_count >= self.requirements['digits']['value']
        requirements.append({
            'name': 'Numbers',
            'description': self.requirements['digits']['description'],
            'met': digits_met,
            'icon': '✅' if digits_met else '❌'
        })
        if digits_met:
            score += 1
        else:
            suggestions.append("Add numbers (0-9)")
        
        # Check special characters
        special_chars = set('!@#$%^&*(),.?":{}|<>[]\\;\'`~_+-=')
        special_count = sum(1 for c in password if c in special_chars)
        special_met = special_count >= self.requirements['special']['value']
        requirements.append({
            'name': 'Special Characters',
            'description': self.requirements['special']['description'],
            'met': special_met,
            'icon': '✅' if special_met else '❌'
        })
        if special_met:
            score += 1
        else:
            suggestions.append("Add special characters (!@#$%^&*)")
        
        # Check for weak patterns
        password_lower = password.lower()
        weak_found = []
        for pattern in self.weak_patterns:
            if pattern in password_lower:
                weak_found.append(pattern)
                score -= 1
        
        if weak_found:
            suggestions.append(f"Avoid common patterns: {', '.join(weak_found)}")
        
        # Check for repeated characters
        if len(set(password)) < len(password) * 0.7:
            suggestions.append("Avoid too many repeated characters")
            score -= 1
        
        # Calculate entropy (password complexity)
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in special_chars for c in password):
            charset_size += len(special_chars)
        
        entropy = len(password) * (charset_size.bit_length() - 1) if charset_size > 0 else 0
        
        # Determine strength level
        max_score = 6
        normalized_score = max(0, min(score, max_score))
        
        if normalized_score >= 5 and entropy >= 50:
            strength_level = 'strong'
            is_valid = True
        elif normalized_score >= 3 and entropy >= 30:
            strength_level = 'medium'
            is_valid = True
        elif normalized_score >= 1:
            strength_level = 'weak'
            is_valid = False
        else:
            strength_level = 'very_weak'
            is_valid = False
        
        return {
            'is_valid': is_valid,
            'strength_score': normalized_score,
            'strength_level': strength_level,
            'requirements': requirements,
            'suggestions': suggestions[:3],  # Limit to top 3 suggestions
            'entropy': entropy
        }
    
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a cryptographically strong password"""
        if length < 12:
            length = 12
        
        # Ensure we have at least one character from each required category
        chars = []
        chars.append(secrets.choice(string.ascii_lowercase))
        chars.append(secrets.choice(string.ascii_uppercase))
        chars.append(secrets.choice(string.digits))
        chars.append(secrets.choice('!@#$%^&*'))
        
        # Fill the rest with random characters from all categories
        all_chars = string.ascii_letters + string.digits + '!@#$%^&*'
        for _ in range(length - 4):
            chars.append(secrets.choice(all_chars))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(chars)
        return ''.join(chars)

class OTPManager:
    """Manage OTP generation, verification, and email sending"""
    
    @staticmethod
    def generate_otp(length: int = 6) -> str:
        """Generate a random OTP"""
        return ''.join([str(random.randint(0, 9)) for _ in range(length)])
    
    @staticmethod
    def create_otp(email: str, otp_type: str = 'verification') -> Optional[str]:
        """Create and store OTP in database"""
        conn = create_connection()
        try:
            c = conn.cursor()
            otp_id = str(uuid.uuid4())
            otp_code = OTPManager.generate_otp()
            expires_at = datetime.now(pytz.utc) + timedelta(minutes=10)  # 10 minute expiry
            created_at = datetime.now(pytz.utc)
            
            c.execute('''INSERT INTO otps (id, email, otp_code, otp_type, expires_at, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      (otp_id, email, otp_code, otp_type, expires_at, created_at))
            conn.commit()
            return otp_code
        except Error as e:
            log_error(f"Error creating OTP: {e}")
            return None
        finally:
            conn.close()
    
    @staticmethod
    def verify_otp(email: str, otp_code: str, otp_type: str = 'verification') -> bool:
        """Verify OTP code"""
        conn = create_connection()
        try:
            c = conn.cursor()
            current_time = datetime.now(pytz.utc)
            
            c.execute('''SELECT id FROM otps 
                         WHERE email = ? AND otp_code = ? AND otp_type = ? 
                         AND expires_at > ? AND used = FALSE''', 
                      (email, otp_code, otp_type, current_time))
            result = c.fetchone()
            
            if result:
                # Mark OTP as used
                c.execute('''UPDATE otps SET used = TRUE WHERE id = ?''', (result[0],))
                conn.commit()
                return True
            return False
        except Error as e:
            log_error(f"Error verifying OTP: {e}")
            return False
        finally:
            conn.close()
    
    @staticmethod
    def send_otp_email(email: str, otp_code: str, otp_type: str = 'verification') -> bool:
        """Send OTP via email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = email
            
            if otp_type == 'verification':
                msg['Subject'] = "FreeToDo - Email Verification Code"
                body = f"""
                Hello!
                
                Your email verification code is: {otp_code}
                
                This code will expire in 10 minutes.
                
                If you didn't request this verification, please ignore this email.
                
                Best regards,
                The FreeToDo Team
                """
            elif otp_type == 'password_reset':
                msg['Subject'] = "FreeToDo - Password Reset Code"
                body = f"""
                Hello!
                
                Your password reset code is: {otp_code}
                
                This code will expire in 10 minutes.
                
                If you didn't request a password reset, please ignore this email and your password will remain unchanged.
                
                Best regards,
                The FreeToDo Team
                """
            else:
                msg['Subject'] = f"FreeToDo - Verification Code"
                body = f"""
                Hello!
                
                Your verification code is: {otp_code}
                
                This code will expire in 10 minutes.
                
                Best regards,
                The FreeToDo Team
                """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            text = msg.as_string()
            server.sendmail(EMAIL_CONFIG['sender_email'], email, text)
            server.quit()
            
            return True
        except Exception as e:
            log_error(f"Email sending error: {e}")
            return False

class GoogleOAuthManager:
    """Handle Google OAuth authentication"""
    
    @staticmethod
    def get_auth_url() -> str:
        """Generate Google OAuth URL"""
        params = {
            'client_id': GOOGLE_OAUTH_CONFIG['client_id'],
            'redirect_uri': GOOGLE_OAUTH_CONFIG['redirect_uri'],
            'scope': GOOGLE_OAUTH_CONFIG['scope'],
            'response_type': 'code',
            'access_type': 'offline',
            'prompt': 'consent',
            'state': secrets.token_urlsafe(32)
        }
        
        # Store state in session for verification
        st.session_state.oauth_state = params['state']
        
        base_url = "https://accounts.google.com/o/oauth2/auth"
        return f"{base_url}?{urllib.parse.urlencode(params)}"
    
    @staticmethod
    def exchange_code_for_token(code: str, state: str) -> Optional[Dict]:
        """Exchange authorization code for access token"""
        # Verify state parameter
        if state != st.session_state.get('oauth_state'):
            return None
        
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'client_id': GOOGLE_OAUTH_CONFIG['client_id'],
            'client_secret': GOOGLE_OAUTH_CONFIG['client_secret'],
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': GOOGLE_OAUTH_CONFIG['redirect_uri']
        }
        
        try:
            response = requests.post(token_url, data=data)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            log_error(f"OAuth token exchange error: {e}")
            return None
    
    @staticmethod
    def get_user_info(access_token: str) -> Optional[Dict]:
        """Get user information from Google"""
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            response = requests.get('https://www.googleapis.com/oauth2/v2/userinfo', headers=headers)
            return response.json() if response.status_code == 200 else None
        except Exception as e:
            log_error(f"OAuth user info error: {e}")
            return None

class PasswordStrengthValidator:
    """Password strength validation and suggestions"""
    
    def __init__(self):
        self.validator = PasswordValidator()
        self.validator\
            .min(8)\
            .max(100)\
            .has().uppercase()\
            .has().lowercase()\
            .has().digits()\
            .has().symbols()
    
    def validate_password(self, password: str) -> Dict[str, Union[bool, str, List[str]]]:
        """Validate password strength and return detailed feedback"""
        result = {
            'is_valid': False,
            'score': 0,
            'suggestions': [],
            'strength': 'weak'
        }
        
        if not password:
            result['suggestions'].append("Password cannot be empty")
            return result
        
        # Check length
        if len(password) < 8:
            result['suggestions'].append("Password must be at least 8 characters long")
        elif len(password) < 12:
            result['suggestions'].append("Consider using a longer password (12+ characters)")
        
        # Check for common weak patterns
        weak_patterns = [
            ('123456', 'Avoid sequential numbers'),
            ('password', 'Avoid common words'),
            ('qwerty', 'Avoid keyboard patterns'),
            ('abc123', 'Avoid simple patterns'),
            ('admin', 'Avoid common admin terms'),
            ('user', 'Avoid common user terms'),
            ('test', 'Avoid common test terms'),
            ('welcome', 'Avoid common welcome terms'),
            ('hello', 'Avoid common greeting terms'),
            ('letmein', 'Avoid common phrases'),
        ]
        
        password_lower = password.lower()
        for pattern, suggestion in weak_patterns:
            if pattern in password_lower:
                result['suggestions'].append(suggestion)
        
        # Check for repeated characters
        if len(set(password)) < len(password) * 0.7:
            result['suggestions'].append("Avoid repeated characters")
        
        # Calculate strength score
        score = 0
        
        # Length score
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if len(password) >= 16:
            score += 1
        
        # Character variety score
        if re.search(r'[a-z]', password):
            score += 1
        if re.search(r'[A-Z]', password):
            score += 1
        if re.search(r'\d', password):
            score += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        
        # Deduct points for weak patterns
        for pattern, _ in weak_patterns:
            if pattern in password_lower:
                score -= 1
        
        # Determine strength level
        if score >= 4:
            result['strength'] = 'strong'
            result['is_valid'] = True
        elif score >= 2:
            result['strength'] = 'medium'
            result['is_valid'] = True
        else:
            result['strength'] = 'weak'
            result['is_valid'] = False
        
        result['score'] = max(0, score)
        
        # Add positive suggestions
        if score < 4:
            if not re.search(r'[A-Z]', password):
                result['suggestions'].append("Add uppercase letters")
            if not re.search(r'[a-z]', password):
                result['suggestions'].append("Add lowercase letters")
            if not re.search(r'\d', password):
                result['suggestions'].append("Add numbers")
            if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
                result['suggestions'].append("Add special characters")
            if len(password) < 12:
                result['suggestions'].append("Make it longer")
        
        return result
    
    def generate_strong_password(self) -> str:
        """Generate a strong password"""
        length = 16
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        while True:
            password = ''.join(secrets.choice(characters) for _ in range(length))
            validation = self.validate_password(password)
            if validation['is_valid'] and validation['strength'] == 'strong':
                return password

class EmailValidator:
    """Email validation and verification"""
    
    @staticmethod
    def validate_email(email: str) -> Union[str, None]:
        """Validate email format"""
        if not email or not email.strip():
            return "Email cannot be empty"
        
        try:
            # Validate email format
            valid = validate_email(email)
            email = valid.email
            return None
        except EmailNotValidError as e:
            return f"Invalid email format: {str(e)}"
    
    @staticmethod
    def send_verification_email(email: str, username: str, token: str) -> bool:
        """Send verification email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = email
            msg['Subject'] = "Verify your FreeToDo account"
            
            body = f"""
            Hello {username}!
            
            Welcome to FreeToDo! Please verify your email address by clicking the link below:
            
            Verification Link: http://localhost:8501/?token={token}
            
            If you didn't create this account, please ignore this email.
            
            Best regards,
            The FreeToDo Team
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port'])
            server.starttls()
            server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
            text = msg.as_string()
            server.sendmail(EMAIL_CONFIG['sender_email'], email, text)
            server.quit()
            
            return True
        except Exception as e:
            log_error(f"Email sending error: {e}")
            return False

class InputValidator:
    """Enhanced input validation with comprehensive checks"""
    
    @staticmethod
    def validate_username(username: str) -> Union[str, None]:
        """Validate username with comprehensive checks"""
        if not username or len(username.strip()) < 3:
            return "Username must be at least 3 characters long"
        if len(username) > 50:
            return "Username must be less than 50 characters"
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return "Username can only contain letters, numbers, and underscores"
        
        # Check for reserved words
        reserved_words = ['admin', 'root', 'system', 'user', 'guest', 'test', 'demo']
        if username.lower() in reserved_words:
            return "Username cannot be a reserved word"
        
        # Check for common patterns
        if re.match(r'^\d+$', username):
            return "Username cannot be only numbers"
        
        return None
    
    @staticmethod
    def validate_password(password: str) -> Union[str, None]:
        """Basic password validation"""
        if not password or len(password) < 8:
            return "Password must be at least 8 characters long"
        if len(password) > 100:
            return "Password is too long"
        return None
    
    @staticmethod
    def validate_email(email: str) -> Union[str, None]:
        """Validate email format"""
        return EmailValidator.validate_email(email)
    
    @staticmethod
    def validate_task_title(title: str) -> Union[str, None]:
        """Validate task title"""
        if not title or len(title.strip()) == 0:
            return "Task title cannot be empty"
        if len(title) > 200:
            return "Task title is too long (max 200 characters)"
        
        # Check for inappropriate content
        inappropriate_words = ['spam', 'advertisement', 'promotion']
        if any(word in title.lower() for word in inappropriate_words):
            return "Task title contains inappropriate content"
        
        return None
    
    @staticmethod
    def validate_list_name(name: str) -> Union[str, None]:
        """Validate list name"""
        if not name or len(name.strip()) == 0:
            return "List name cannot be empty"
        if len(name) > 100:
            return "List name is too long (max 100 characters)"
        
        # Check for reserved list names
        reserved_names = ['My Day', 'Important', 'Planned', 'Tasks']
        if name in reserved_names:
            return f"'{name}' is a reserved list name"
        
        return None
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize user input to prevent XSS"""
        # Remove potentially dangerous HTML tags
        dangerous_tags = ['<script>', '</script>', '<iframe>', '</iframe>', '<object>', '</object>']
        sanitized = text
        for tag in dangerous_tags:
            sanitized = sanitized.replace(tag, '')
        
        # Remove JavaScript events
        js_events = ['onclick', 'onload', 'onerror', 'onmouseover']
        for event in js_events:
            sanitized = re.sub(f'{event}=["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()

# Data Access Layer
class DatabaseManager:
    def create_user(self, username: str, email: str, password: str, google_id: str = None, profile_picture: str = None) -> Optional[str]:
        conn = create_connection()
        try:
            c = conn.cursor()
            user_id = str(uuid.uuid4())
            created_at = datetime.now(pytz.utc)
            hashed_pw = hash_password(password) if password else None
            verification_token = secrets.token_urlsafe(32) if not google_id else None
            
            c.execute('''INSERT INTO users (id, username, email, password, verification_token, 
                                          google_id, profile_picture, email_verified, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                      (user_id, username, email, hashed_pw, verification_token, 
                       google_id, profile_picture, bool(google_id), created_at))
            conn.commit()
            
            # Send verification email for regular registration
            if not google_id:
                if EmailValidator.send_verification_email(email, username, verification_token):
                    st.success("Registration successful! Please check your email to verify your account.")
                else:
                    st.warning("Registration successful, but verification email could not be sent. Please contact support.")
            
            # Create default lists for new user
            self.create_default_lists(user_id)
            return user_id
        except Error as e:
            st.error(f"Error creating user: {e}")
            log_error(f"Error creating user: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_by_google_id(self, google_id: str) -> Optional[Tuple]:
        """Get user by Google ID"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, username, email FROM users WHERE google_id = ?''', (google_id,))
            return c.fetchone()
        except Error as e:
            log_error(f"Error getting user by Google ID: {e}")
            return None
        finally:
            conn.close()
    
    def get_user_by_email(self, email: str) -> Optional[Tuple]:
        """Get user by email"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, username, email, password FROM users WHERE email = ?''', (email,))
            return c.fetchone()
        except Error as e:
            log_error(f"Error getting user by email: {e}")
            return None
        finally:
            conn.close()
    
    def create_password_reset_token(self, email: str) -> Optional[str]:
        """Create password reset token"""
        conn = create_connection()
        try:
            c = conn.cursor()
            reset_token = secrets.token_urlsafe(32)
            expires_at = datetime.now(pytz.utc) + timedelta(hours=1)  # 1 hour expiry
            
            c.execute('''UPDATE users 
                         SET reset_token = ?, reset_token_expires = ?
                         WHERE email = ?''', 
                      (reset_token, expires_at, email))
            conn.commit()
            
            if c.rowcount > 0:
                return reset_token
            return None
        except Error as e:
            log_error(f"Error creating reset token: {e}")
            return None
        finally:
            conn.close()
    
    def verify_reset_token(self, token: str) -> Optional[str]:
        """Verify password reset token and return email"""
        conn = create_connection()
        try:
            c = conn.cursor()
            current_time = datetime.now(pytz.utc)
            c.execute('''SELECT email FROM users 
                         WHERE reset_token = ? AND reset_token_expires > ?''', 
                      (token, current_time))
            result = c.fetchone()
            return result[0] if result else None
        except Error as e:
            log_error(f"Error verifying reset token: {e}")
            return None
        finally:
            conn.close()
    
    def reset_password(self, email: str, new_password: str) -> bool:
        """Reset user password"""
        conn = create_connection()
        try:
            c = conn.cursor()
            hashed_pw = hash_password(new_password)
            c.execute('''UPDATE users 
                         SET password = ?, reset_token = NULL, reset_token_expires = NULL
                         WHERE email = ?''', 
                      (hashed_pw, email))
            conn.commit()
            return c.rowcount > 0
        except Error as e:
            log_error(f"Error resetting password: {e}")
            return False
        finally:
            conn.close()
    
    def update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''UPDATE users SET last_login = ? WHERE id = ?''', 
                      (datetime.now(pytz.utc), user_id))
            conn.commit()
        except Error as e:
            log_error(f"Error updating last login: {e}")
        finally:
            conn.close()
    
    def verify_email(self, token: str) -> bool:
        """Verify user email with token"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''UPDATE users 
                         SET email_verified = TRUE, verification_token = NULL
                         WHERE verification_token = ?''', (token,))
            conn.commit()
            return c.rowcount > 0
        except Error as e:
            st.error(f"Error verifying email: {e}")
            log_error(f"Error verifying email: {e}")
            return False
        finally:
            conn.close()
    
    def check_email_verified(self, user_id: str) -> bool:
        """Check if user's email is verified"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT email_verified FROM users WHERE id = ?''', (user_id,))
            result = c.fetchone()
            return result[0] if result else False
        except Error as e:
            log_error(f"Error checking email verification: {e}")
            return False
        finally:
            conn.close()
    
    def resend_verification_email(self, user_id: str) -> bool:
        """Resend verification email"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT username, email FROM users WHERE id = ?''', (user_id,))
            result = c.fetchone()
            if result:
                username, email = result
                new_token = secrets.token_urlsafe(32)
                c.execute('''UPDATE users SET verification_token = ? WHERE id = ?''', (new_token, user_id))
                conn.commit()
                return EmailValidator.send_verification_email(email, username, new_token)
            return False
        except Error as e:
            log_error(f"Error resending verification email: {e}")
            return False
        finally:
            conn.close()

    def authenticate_user(self, username: str, password: str) -> Optional[str]:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, password FROM users 
                         WHERE username = ?''', (username,))
            result = c.fetchone()
            if result and check_password(password, result[1]):
                self.update_last_login(result[0])
                return result[0]
            return None
        except Error as e:
            st.error(f"Authentication error: {e}")
            log_error(f"Authentication error: {e}")
            return None
        finally:
            conn.close()
            
    def create_default_lists(self, user_id: str):
        conn = create_connection()
        try:
            c = conn.cursor()
            created_at = datetime.now(pytz.utc)
            for list_name, list_color, list_icon in get_default_lists():
                c.execute('''SELECT id FROM lists WHERE user_id = ? AND name = ?''', (user_id, list_name))
                if not c.fetchone():
                    list_id = str(uuid.uuid4())
                    c.execute('''INSERT INTO lists (id, user_id, name, color, icon, created_at)
                                 VALUES (?, ?, ?, ?, ?, ?)''', 
                              (list_id, user_id, list_name, list_color, list_icon, created_at))
            conn.commit()
        except Error as e:
            st.error(f"Error creating default lists: {e}")
            log_error(f"Error creating default lists: {e}")
        finally:
            conn.close()
            
    def create_list(self, user_id: str, name: str, color: str = "#0078d7", icon: str = "list") -> Optional[str]:
        conn = create_connection()
        try:
            # Validate list name
            name = InputValidator.sanitize_input(name)
            name_error = InputValidator.validate_list_name(name)
            if name_error:
                st.error(name_error)
                return None
            
            c = conn.cursor()
            list_id = str(uuid.uuid4())
            created_at = datetime.now(pytz.utc)
            c.execute('''INSERT INTO lists (id, user_id, name, color, icon, created_at)
                         VALUES (?, ?, ?, ?, ?, ?)''', 
                      (list_id, user_id, name, color, icon, created_at))
            conn.commit()
            return list_id
        except Error as e:
            st.error(f"Error creating list: {e}")
            log_error(f"Error creating list: {e}")
            return None
        finally:
            conn.close()
            
    def get_lists(self, user_id: str) -> List[Tuple[str, str, str, str]]:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, name, color, icon FROM lists 
                         WHERE user_id = ? 
                         ORDER BY name = 'My Day' DESC, 
                                  name = 'Important' DESC, 
                                  name = 'Planned' DESC, 
                                  name = 'Tasks' DESC, 
                                  name ASC''', 
                      (user_id,))
            return c.fetchall()
        except Error as e:
            st.error(f"Error getting lists: {e}")
            log_error(f"Error getting lists: {e}")
            return []
        finally:
            conn.close()
            
    def create_task(self, user_id: str, list_id: str, title: str, 
                    description: str = "", due_date: Optional[datetime] = None, 
                    reminder: Optional[datetime] = None, is_important: bool = False) -> Optional[str]:
        conn = create_connection()
        try:
            # Validate task inputs
            title = InputValidator.sanitize_input(title)
            description = InputValidator.sanitize_input(description)
            
            title_error = InputValidator.validate_task_title(title)
            if title_error:
                st.error(title_error)
                return None
            
            c = conn.cursor()
            task_id = str(uuid.uuid4())
            created_at = updated_at = datetime.now(pytz.utc)
            c.execute('''INSERT INTO tasks 
                         (id, list_id, user_id, title, description, due_date, reminder, 
                          is_completed, is_important, created_at, updated_at, completed_at, recurrence_pattern)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', 
                      (task_id, list_id, user_id, title, description, 
                       due_date.isoformat() if due_date else None, 
                       reminder.isoformat() if reminder else None, 
                       False, is_important, created_at, updated_at, None, None))
            conn.commit()
            return task_id
        except Error as e:
            st.error(f"Error creating task: {e}")
            log_error(f"Error creating task: {e}")
            return None
        finally:
            conn.close()
            
    def get_tasks(self, user_id: str, list_id: str, include_completed: bool = False) -> List[Tuple]:
        conn = create_connection()
        try:
            c = conn.cursor()
            if include_completed:
                c.execute('''SELECT id, title, description, due_date, reminder, 
                                    is_completed, is_important, created_at
                             FROM tasks 
                             WHERE user_id = ? AND list_id = ?
                             ORDER BY is_completed ASC, 
                                      CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, 
                                      due_date ASC, 
                                      created_at DESC''', 
                          (user_id, list_id))
            else:
                c.execute('''SELECT id, title, description, due_date, reminder, 
                                    is_completed, is_important, created_at
                             FROM tasks 
                             WHERE user_id = ? AND list_id = ? AND is_completed = ?
                             ORDER BY CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, 
                                      due_date ASC, 
                                      created_at DESC''', 
                          (user_id, list_id, False))
            return c.fetchall()
        except Error as e:
            st.error(f"Error getting tasks: {e}")
            log_error(f"Error getting tasks: {e}")
            return []
        finally:
            conn.close()
            
    def get_all_tasks(self, user_id: str) -> List[Tuple]:
        """Get all tasks for a user (for 'Tasks' smart list)"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, title, description, due_date, reminder, 
                                is_completed, is_important, created_at
                         FROM tasks 
                         WHERE user_id = ?
                         ORDER BY is_completed ASC, 
                                  CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, 
                                  due_date ASC, 
                                  created_at DESC''', 
                      (user_id,))
            return c.fetchall()
        except Error as e:
            st.error(f"Error getting all tasks: {e}")
            log_error(f"Error getting all tasks: {e}")
            return []
        finally:
            conn.close()
            
    def get_planned_tasks(self, user_id: str) -> List[Tuple]:
        """Get all tasks with a due date (for 'Planned' smart list)"""
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, title, description, due_date, reminder, 
                                is_completed, is_important, created_at
                         FROM tasks 
                         WHERE user_id = ? AND due_date IS NOT NULL
                         ORDER BY is_completed ASC, 
                                  due_date ASC, 
                                  created_at DESC''', 
                      (user_id,))
            return c.fetchall()
        except Error as e:
            st.error(f"Error getting planned tasks: {e}")
            log_error(f"Error getting planned tasks: {e}")
            return []
        finally:
            conn.close()
            
    def update_task_completion(self, task_id: str, is_completed: bool) -> bool:
        conn = create_connection()
        try:
            c = conn.cursor()
            completed_at = datetime.now(pytz.utc) if is_completed else None
            c.execute('''UPDATE tasks 
                         SET is_completed = ?, completed_at = ?, updated_at = ?
                         WHERE id = ?''', 
                      (is_completed, completed_at, datetime.now(pytz.utc), task_id))
            conn.commit()
            return True
        except Error as e:
            st.error(f"Error updating task: {e}")
            log_error(f"Error updating task: {e}")
            return False
        finally:
            conn.close()
            
    def delete_task(self, task_id: str) -> bool:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
            c.execute('DELETE FROM subtasks WHERE task_id = ?', (task_id,))
            conn.commit()
            return True
        except Error as e:
            st.error(f"Error deleting task: {e}")
            log_error(f"Error deleting task: {e}")
            return False
        finally:
            conn.close()
            
    def get_my_day_tasks(self, user_id: str) -> List[Tuple]:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT l.id FROM lists l 
                         WHERE l.user_id = ? AND l.name = 'My Day' ''', 
                      (user_id,))
            my_day_list = c.fetchone()
            if my_day_list:
                return self.get_tasks(user_id, my_day_list[0])
            return []
        except Error as e:
            st.error(f"Error getting My Day tasks: {e}")
            log_error(f"Error getting My Day tasks: {e}")
            return []
        finally:
            conn.close()
            
    def add_to_my_day(self, user_id: str, task_id: str) -> bool:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id FROM lists 
                         WHERE user_id = ? AND name = 'My Day' ''', 
                      (user_id,))
            my_day_list = c.fetchone()
            if not my_day_list:
                self.create_default_lists(user_id)
                c.execute('''SELECT id FROM lists 
                             WHERE user_id = ? AND name = 'My Day' ''', 
                          (user_id,))
                my_day_list = c.fetchone()
            c.execute('''UPDATE tasks 
                         SET list_id = ?, updated_at = ?
                         WHERE id = ?''', 
                      (my_day_list[0], datetime.now(pytz.utc), task_id))
            conn.commit()
            return True
        except Error as e:
            st.error(f"Error adding to My Day: {e}")
            log_error(f"Error adding to My Day: {e}")
            return False
        finally:
            conn.close()
            
    def toggle_task_importance(self, task_id: str, is_important: bool) -> bool:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''UPDATE tasks 
                         SET is_important = ?, updated_at = ?
                         WHERE id = ?''', 
                      (is_important, datetime.now(pytz.utc), task_id))
            conn.commit()
            return True
        except Error as e:
            st.error(f"Error updating task importance: {e}")
            log_error(f"Error updating task importance: {e}")
            return False
        finally:
            conn.close()

    def get_important_tasks(self, user_id: str) -> List[Tuple]:
        conn = create_connection()
        try:
            c = conn.cursor()
            c.execute('''SELECT id, title, description, due_date, reminder, 
                                is_completed, is_important, created_at
                         FROM tasks 
                         WHERE user_id = ? AND is_important = ? AND is_completed = ?
                         ORDER BY CASE WHEN due_date IS NULL THEN 1 ELSE 0 END, 
                                  due_date ASC, 
                                  created_at DESC''', 
                      (user_id, True, False))
            return c.fetchall()
        except Error as e:
            st.error(f"Error getting important tasks: {e}")
            log_error(f"Error getting important tasks: {e}")
            return []
        finally:
            conn.close()
            
    def delete_list(self, list_id: str) -> bool:
        conn = create_connection()
        try:
            c = conn.cursor()
            # Delete all tasks and subtasks in the list
            c.execute('SELECT id FROM tasks WHERE list_id = ?', (list_id,))
            task_ids = [row[0] for row in c.fetchall()]
            for task_id in task_ids:
                c.execute('DELETE FROM subtasks WHERE task_id = ?', (task_id,))
            c.execute('DELETE FROM tasks WHERE list_id = ?', (list_id,))
            # Delete the list itself
            c.execute('DELETE FROM lists WHERE id = ?', (list_id,))
            conn.commit()
            return True
        except Error as e:
            st.error(f"Error deleting list: {e}")
            log_error(f"Error deleting list: {e}")
            return False
        finally:
            conn.close()

# UI Components
def show_live_password_validator(password: str, key: str = "password_validator") -> Dict:
    """Show live password validation with real-time feedback"""
    validator = LivePasswordValidator()
    result = validator.validate_live(password)
    
    if password:
        # Strength indicator
        strength_colors = {
            'none': '#gray',
            'very_weak': '#ff4444',
            'weak': '#ff8800', 
            'medium': '#ffaa00',
            'strong': '#00cc44'
        }
        
        strength_color = strength_colors.get(result['strength_level'], '#gray')
        
        # Create strength bar
        strength_percentage = (result['strength_score'] / 6) * 100
        
        st.markdown(f"""
        <div style="margin: 10px 0;">
            <div style="display: flex; align-items: center; gap: 10px;">
                <span style="font-weight: 600;">Strength:</span>
                <div style="flex: 1; background: #f0f0f0; border-radius: 10px; height: 8px;">
                    <div style="width: {strength_percentage}%; background: {strength_color}; height: 100%; border-radius: 10px; transition: all 0.3s;"></div>
                </div>
                <span style="color: {strength_color}; font-weight: 600; text-transform: capitalize;">
                    {result['strength_level'].replace('_', ' ')}
                </span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Requirements checklist
        if result['requirements']:
            st.markdown("**Requirements:**")
            cols = st.columns(2)
            for i, req in enumerate(result['requirements']):
                with cols[i % 2]:
                    color = "green" if req['met'] else "red"
                    st.markdown(f":{color}[{req['icon']} {req['description']}]")
        
        # Suggestions
        if result['suggestions']:
            st.markdown("**Suggestions:**")
            for suggestion in result['suggestions']:
                st.markdown(f"• {suggestion}")
        
        # Generate strong password button
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("🎲 Generate Strong Password", key=f"gen_pass_{key}"):
                strong_password = validator.generate_strong_password()
                st.session_state[f'generated_password_{key}'] = strong_password
                st.success("Strong password generated!")
                st.rerun()
        
        with col2:
            if f'generated_password_{key}' in st.session_state:
                if st.button("📋 Copy Generated", key=f"copy_pass_{key}"):
                    st.code(st.session_state[f'generated_password_{key}'])
    
    return result

def show_otp_verification(email: str, otp_type: str = 'verification') -> bool:
    """Show OTP verification interface"""
    st.subheader("Enter Verification Code")
    st.write(f"We've sent a 6-digit code to {email}")
    
    # OTP input
    otp_code = st.text_input("Enter 6-digit code", max_chars=6, key=f"otp_{otp_type}")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        if st.button("Verify Code", type="primary"):
            if len(otp_code) == 6 and otp_code.isdigit():
                if OTPManager.verify_otp(email, otp_code, otp_type):
                    st.success("✅ Code verified successfully!")
                    return True
                else:
                    st.error("❌ Invalid or expired code")
            else:
                st.error("Please enter a valid 6-digit code")
    
    with col2:
        if st.button("Resend Code"):
            new_otp = OTPManager.create_otp(email, otp_type)
            if new_otp and OTPManager.send_otp_email(email, new_otp, otp_type):
                st.success("New code sent!")
            else:
                st.error("Failed to send code")
    
    return False

def show_otp_verification_interface(db: DatabaseManager):
    """Show OTP verification interface with consistent styling"""
    st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Email Verification</h3>", unsafe_allow_html=True)
    
    if 'pending_email' in st.session_state:
        email = st.session_state.pending_email
        
        # Create and send OTP
        if 'otp_sent' not in st.session_state:
            otp_code = OTPManager.create_otp(email, 'verification')
            if otp_code and OTPManager.send_otp_email(email, otp_code, 'verification'):
                st.session_state.otp_sent = True
                st.success(f"✅ Verification code sent to {email}")
            else:
                st.error("❌ Failed to send verification code")
        
        st.markdown(f"<p style='text-align: center; color: #666; margin-bottom: 1.5rem;'>We've sent a 6-digit code to <strong>{email}</strong></p>", unsafe_allow_html=True)
        
        otp_code = st.text_input("Enter 6-digit code", max_chars=6, placeholder="000000")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            if st.button("Verify Code", type="primary", use_container_width=True):
                if len(otp_code) == 6 and otp_code.isdigit():
                    if OTPManager.verify_otp(email, otp_code, 'verification'):
                        # Mark email as verified in database
                        if 'pending_user_id' in st.session_state:
                            conn = create_connection()
                            try:
                                c = conn.cursor()
                                c.execute('''UPDATE users SET email_verified = TRUE WHERE id = ?''', 
                                          (st.session_state.pending_user_id,))
                                conn.commit()
                                
                                # Clear temporary session data
                                for key in ['pending_user_id', 'pending_email', 'auth_tab', 'otp_sent']:
                                    if key in st.session_state:
                                        del st.session_state[key]
                                
                                st.success("✅ Email verified successfully! You can now log in.")
                                st.session_state.auth_tab = 'Login'
                                st.rerun()
                            except Error as e:
                                st.error(f"❌ Database error: {e}")
                            finally:
                                conn.close()
                    else:
                        st.error("❌ Invalid or expired code")
                else:
                    st.error("❌ Please enter a valid 6-digit code")
        
        with col2:
            if st.button("Resend Code", use_container_width=True):
                new_otp = OTPManager.create_otp(email, 'verification')
                if new_otp and OTPManager.send_otp_email(email, new_otp, 'verification'):
                    st.success("✅ New code sent!")
                else:
                    st.error("❌ Failed to send code")
        
        # Back to login option
        st.markdown("<div style='text-align: center; margin-top: 1.5rem;'>", unsafe_allow_html=True)
        if st.button("← Back to Login", use_container_width=True):
            for key in ['pending_user_id', 'pending_email', 'auth_tab', 'otp_sent']:
                if key in st.session_state:
                    del st.session_state[key]
            st.session_state.auth_tab = 'Login'
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

def show_google_oauth_button():
    """Show Google OAuth login button with consistent styling"""
    auth_url = GoogleOAuthManager.get_auth_url()
    
    # Custom Google OAuth button with consistent styling
    google_button_html = f"""
    <div style="margin: 15px 0;">
        <a href="{auth_url}" target="_self" style="text-decoration: none;">
            <div style="
                display: flex;
                align-items: center;
                justify-content: center;
                background: white;
                border: 1px solid #dadce0;
                border-radius: 6px;
                padding: 10px 16px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                font-size: 14px;
                font-weight: 500;
                color: #3c4043;
                cursor: pointer;
                transition: all 0.2s ease;
                min-height: 44px;
                width: 100%;
                box-sizing: border-box;
            " onmouseover="this.style.backgroundColor='#f8f9fa'; this.style.borderColor='#c1c7cd'; this.style.boxShadow='0 1px 3px rgba(0,0,0,0.1)';" 
               onmouseout="this.style.backgroundColor='white'; this.style.borderColor='#dadce0'; this.style.boxShadow='none';">
                <svg width="18" height="18" viewBox="0 0 24 24" style="margin-right: 12px;">
                    <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                    <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                    <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                    <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Continue with Google
            </div>
        </a>
    </div>
    """
    
    components.html(google_button_html, height=70)

def show_password_reset_interface(db: DatabaseManager):
    """Show password reset interface with consistent styling"""
    if 'reset_step' not in st.session_state:
        st.session_state.reset_step = 'request'
    
    if st.session_state.reset_step == 'request':
        st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Reset Password</h3>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #666; margin-bottom: 1.5rem;'>Enter your email address to receive a reset code</p>", unsafe_allow_html=True)
        
        email = st.text_input("Email Address", placeholder="Enter your email address")
        
        if st.button("Send Reset Code", type="primary", use_container_width=True):
            if email:
                email_error = InputValidator.validate_email(email)
                if email_error:
                    st.error(f"❌ {email_error}")
                else:
                    # Check if user exists
                    user = db.get_user_by_email(email)
                    if user:
                        # Create and send OTP
                        otp_code = OTPManager.create_otp(email, 'password_reset')
                        if otp_code and OTPManager.send_otp_email(email, otp_code, 'password_reset'):
                            st.session_state.reset_email = email
                            st.session_state.reset_step = 'verify_otp'
                            st.success("✅ Reset code sent to your email!")
                            st.rerun()
                        else:
                            st.error("❌ Failed to send reset code")
                    else:
                        st.error("❌ No account found with this email address")
            else:
                st.error("❌ Please enter your email address")
    
    elif st.session_state.reset_step == 'verify_otp':
        st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Enter Reset Code</h3>", unsafe_allow_html=True)
        st.markdown(f"<p style='text-align: center; color: #666; margin-bottom: 1.5rem;'>We've sent a reset code to <strong>{st.session_state.reset_email}</strong></p>", unsafe_allow_html=True)
        
        otp_code = st.text_input("Enter 6-digit code", max_chars=6, placeholder="000000")
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            if st.button("Verify Code", type="primary", use_container_width=True):
                if len(otp_code) == 6 and otp_code.isdigit():
                    if OTPManager.verify_otp(st.session_state.reset_email, otp_code, 'password_reset'):
                        st.session_state.reset_step = 'new_password'
                        st.success("✅ Code verified! Set your new password.")
                        st.rerun()
                    else:
                        st.error("❌ Invalid or expired code")
                else:
                    st.error("❌ Please enter a valid 6-digit code")
        
        with col2:
            if st.button("Resend Code", use_container_width=True):
                new_otp = OTPManager.create_otp(st.session_state.reset_email, 'password_reset')
                if new_otp and OTPManager.send_otp_email(st.session_state.reset_email, new_otp, 'password_reset'):
                    st.success("✅ New code sent!")
                else:
                    st.error("❌ Failed to send code")
    
    elif st.session_state.reset_step == 'new_password':
        st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Set New Password</h3>", unsafe_allow_html=True)
        
        new_password = st.text_input("New Password", type="password", key="new_password_reset", placeholder="Enter your new password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your new password")
        
        # Live password validation (outside form)
        validation_result = None
        if new_password:
            validation_result = show_live_password_validator(new_password, "reset")
        
        if st.button("Reset Password", type="primary", use_container_width=True):
            if not new_password or not confirm_password:
                st.error("❌ Please fill in both password fields")
            elif new_password != confirm_password:
                st.error("❌ Passwords don't match")
            elif new_password and 'validation_result' in locals() and not validation_result['is_valid']:
                st.error("❌ Password does not meet strength requirements")
            else:
                if db.reset_password(st.session_state.reset_email, new_password):
                    st.success("✅ Password reset successfully! You can now log in.")
                    # Clear reset session data
                    for key in ['reset_step', 'reset_email']:
                        if key in st.session_state:
                            del st.session_state[key]
                    st.rerun()
                else:
                    st.error("❌ Failed to reset password")

def show_login(db: DatabaseManager):
    """Show enhanced login/register interface with consistent design"""
    # Center the title with consistent styling
    st.markdown("""
    <div style="text-align: center; margin-bottom: 2rem;">
        <h1 style="color: #1f1f1f; font-weight: 600; font-size: 2.5rem; margin-bottom: 0.5rem;">FreeToDo</h1>
        <p style="color: #666; font-size: 1.1rem;">Your personal task management solution</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Check for email verification token in URL
    params = st.query_params
    if 'token' in params:
        token = params['token'][0]
        if db.verify_email(token):
            st.success("✅ Email verified successfully! You can now log in.")
        else:
            st.error("❌ Invalid or expired verification link.")
        st.query_params.clear()
    
    # Check for Google OAuth callback
    if 'code' in params and 'state' in params:
        code = params['code'][0]
        state = params['state'][0]
        
        # Exchange code for token
        token_data = GoogleOAuthManager.exchange_code_for_token(code, state)
        if token_data and 'access_token' in token_data:
            # Get user info from Google
            user_info = GoogleOAuthManager.get_user_info(token_data['access_token'])
            if user_info:
                # Check if user exists
                existing_user = db.get_user_by_google_id(user_info['id'])
                if existing_user:
                    # User exists, log them in
                    user_id, username, email = existing_user
                    st.session_state.user_id = user_id
                    st.session_state.username = username
                    db.update_last_login(user_id)
                    st.success(f"Welcome back, {username}!")
                    st.rerun()
                else:
                    # New user, create account
                    username = user_info.get('name', user_info.get('email', '').split('@')[0])
                    # Ensure unique username
                    base_username = re.sub(r'[^a-zA-Z0-9_]', '_', username)
                    unique_username = base_username
                    counter = 1
                    while db.get_user_by_email(user_info['email']):
                        unique_username = f"{base_username}_{counter}"
                        counter += 1
                    
                    user_id = db.create_user(
                        unique_username,
                        user_info['email'],
                        None,  # No password for Google users
                        user_info['id'],
                        user_info.get('picture')
                    )
                    
                    if user_id:
                        st.session_state.user_id = user_id
                        st.session_state.username = unique_username
                        st.success(f"Welcome to FreeToDo, {unique_username}!")
                        st.rerun()
                    else:
                        st.error("Failed to create account")
            else:
                st.error("Failed to get user information from Google")
        else:
            st.error("Failed to authenticate with Google")
        
        st.query_params.clear()
    
    # Use session state to control which tab is active
    if 'auth_tab' not in st.session_state:
        st.session_state.auth_tab = 'Login'
    
    # Handle OTP verification separately
    if st.session_state.get('auth_tab') == 'OTP_Verification':
        show_otp_verification_interface(db)
        return
    
    # Create a centered container for the form
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        # Get the current tab index safely
        current_tab = st.session_state.get("auth_tab", "Login")
        tab_options = ["Login", "Register", "Reset Password"]
        tab_index = tab_options.index(current_tab) if current_tab in tab_options else 0
        
        # Custom tab styling
        st.markdown("""
        <style>
        div[data-testid="stHorizontalBlock"] > div:first-child {
            gap: 0rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 0px;
            background-color: #f0f2f6;
            border-radius: 8px;
            padding: 4px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 44px;
            background-color: transparent;
            border-radius: 6px;
            color: #666;
            font-weight: 500;
        }
        .stTabs [aria-selected="true"] {
            background-color: white !important;
            color: #1f1f1f !important;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        </style>
        """, unsafe_allow_html=True)
        
        tab = st.radio("", tab_options, index=tab_index, horizontal=True, label_visibility="collapsed")

        if tab == "Login":
            st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Welcome Back!</h3>", unsafe_allow_html=True)
            
            # Google OAuth button
            show_google_oauth_button()
            
            # Divider with consistent styling
            st.markdown("""
            <div style="display: flex; align-items: center; margin: 1.5rem 0;">
                <div style="flex: 1; height: 1px; background: #e0e0e0;"></div>
                <span style="padding: 0 1rem; color: #666; font-size: 14px;">Or sign in with email</span>
                <div style="flex: 1; height: 1px; background: #e0e0e0;"></div>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("login_form"):
                username = st.text_input("Username", placeholder="Enter your username")
                password = st.text_input("Password", type="password", placeholder="Enter your password")
                
                # Consistent button styling
                submit = st.form_submit_button("Sign In", type="primary", use_container_width=True)
                
                if submit:
                    # Sanitize inputs
                    username = InputValidator.sanitize_input(username)
                    password = InputValidator.sanitize_input(password)
                    
                    # Validate inputs
                    username_error = InputValidator.validate_username(username)
                    password_error = InputValidator.validate_password(password)
                    
                    if username_error:
                        st.error(username_error)
                    elif password_error:
                        st.error(password_error)
                    else:
                        user_id = db.authenticate_user(username, password)
                        if user_id:
                            # Check email verification
                            if not db.check_email_verified(user_id):
                                st.warning("⚠️ Please verify your email address before logging in.")
                                col1, col2 = st.columns([1, 1])
                                with col1:
                                    if st.button("📧 Resend verification email", use_container_width=True):
                                        if db.resend_verification_email(user_id):
                                            st.success("Verification email sent!")
                                        else:
                                            st.error("Failed to send verification email")
                                with col2:
                                    if st.button("🔐 Verify with OTP", use_container_width=True):
                                        st.session_state.pending_user_id = user_id
                                        st.session_state.auth_tab = 'OTP_Verification'
                                        st.rerun()
                            else:
                                st.session_state.user_id = user_id
                                st.session_state.username = username
                                st.success("✅ Login successful!")
                                st.rerun()
                        else:
                            st.error("❌ Invalid username or password")
            
            # Forgot password link with consistent styling
            st.markdown("<div style='text-align: center; margin-top: 1rem;'>", unsafe_allow_html=True)
            if st.button("Forgot Password?", type="secondary", use_container_width=True):
                st.session_state.auth_tab = 'Reset Password'
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
        
        elif tab == "Register":
            st.markdown("<h3 style='text-align: center; margin: 1.5rem 0 1rem 0; color: #1f1f1f;'>Create Your Account</h3>", unsafe_allow_html=True)
            
            # Google OAuth button
            show_google_oauth_button()
            
            # Divider with consistent styling
            st.markdown("""
            <div style="display: flex; align-items: center; margin: 1.5rem 0;">
                <div style="flex: 1; height: 1px; background: #e0e0e0;"></div>
                <span style="padding: 0 1rem; color: #666; font-size: 14px;">Or create account with email</span>
                <div style="flex: 1; height: 1px; background: #e0e0e0;"></div>
            </div>
            """, unsafe_allow_html=True)
            
            # Password validation outside form
            new_username = st.text_input("Username", key="reg_username", placeholder="Choose a username")
            new_email = st.text_input("Email", key="reg_email", placeholder="Enter your email address")
            new_password = st.text_input("Password", type="password", key="reg_password", placeholder="Create a strong password")
            confirm_password = st.text_input("Confirm Password", type="password", key="reg_confirm_password", placeholder="Confirm your password")
            
            # Live password validation (outside form)
            validation_result = None
            if new_password:
                validation_result = show_live_password_validator(new_password, "register")
            
            # Use generated password if available
            if 'generated_password_register' in st.session_state:
                new_password = st.session_state.generated_password_register
                st.info(f"💡 Using generated password: `{new_password}`")
            
            with st.form("register_form"):
                submit = st.form_submit_button("Create Account", type="primary", use_container_width=True)
                
                if submit:
                    # Sanitize inputs
                    new_username = InputValidator.sanitize_input(new_username)
                    new_email = InputValidator.sanitize_input(new_email)
                    new_password = InputValidator.sanitize_input(new_password)
                    confirm_password = InputValidator.sanitize_input(confirm_password)
                    
                    # Validate all inputs
                    username_error = InputValidator.validate_username(new_username)
                    email_error = InputValidator.validate_email(new_email)
                    password_error = InputValidator.validate_password(new_password)
                    
                    errors = []
                    if username_error:
                        errors.append(username_error)
                    if email_error:
                        errors.append(email_error)
                    if password_error:
                        errors.append(password_error)
                    
                    if new_password != confirm_password:
                        errors.append("Passwords don't match")
                    
                    # Check password strength
                    if new_password and 'validation_result' in locals() and not validation_result['is_valid']:
                        errors.append("Password does not meet strength requirements")
                    
                    if errors:
                        for error in errors:
                            st.error(f"❌ {error}")
                    else:
                        user_id = db.create_user(new_username, new_email, new_password)
                        if user_id:
                            st.success("✅ Registration successful! Please check your email to verify your account.")
                            st.session_state.pending_user_id = user_id
                            st.session_state.pending_email = new_email
                            st.session_state.auth_tab = 'OTP_Verification'
                            st.rerun()
        
        elif tab == "Reset Password":
            show_password_reset_interface(db)

def show_otp_verification_interface(db: DatabaseManager):
    """Show OTP verification interface"""
    st.subheader("Email Verification")
    
    if 'pending_email' in st.session_state:
        email = st.session_state.pending_email
        
        # Create and send OTP
        if 'otp_sent' not in st.session_state:
            otp_code = OTPManager.create_otp(email, 'verification')
            if otp_code and OTPManager.send_otp_email(email, otp_code, 'verification'):
                st.session_state.otp_sent = True
                st.success(f"Verification code sent to {email}")
            else:
                st.error("Failed to send verification code")
        
        # OTP verification interface
        if show_otp_verification(email, 'verification'):
            # Mark email as verified in database
            if 'pending_user_id' in st.session_state:
                conn = create_connection()
                try:
                    c = conn.cursor()
                    c.execute('''UPDATE users SET email_verified = TRUE WHERE id = ?''', 
                              (st.session_state.pending_user_id,))
                    conn.commit()
                    
                    # Clear temporary session data
                    for key in ['pending_user_id', 'pending_email', 'auth_tab', 'otp_sent']:
                        if key in st.session_state:
                            del st.session_state[key]
                    
                    st.success("Email verified successfully! You can now log in.")
                    st.session_state.auth_tab = 'Login'
                    st.rerun()
                except Error as e:
                    st.error(f"❌ Database error: {e}")
                finally:
                    conn.close()
        
        # Back to login option
        if st.button("← Back to Login"):
            for key in ['pending_user_id', 'pending_email', 'auth_tab', 'otp_sent']:
                if key in st.session_state:
                    del st.session_state[key]
            st.session_state.auth_tab = 'Login'
            st.rerun()

def show_main_interface(db: DatabaseManager):
    """Show the main application interface"""
    # Initialize session state variables
    if 'selected_list' not in st.session_state:
        st.session_state.selected_list = None
    if 'selected_task' not in st.session_state:
        st.session_state.selected_task = None
    if 'show_task_modal' not in st.session_state:
        st.session_state.show_task_modal = False
    
    # Sidebar
    with st.sidebar:
        st.title(f"Welcome, {st.session_state.username}")
        
        # Navigation
        st.subheader("My Lists")
        lists = db.get_lists(st.session_state.user_id)
        
        # Default lists
        for default_name in ["My Day", "Important", "Planned", "Tasks"]:
            if st.button(default_name, use_container_width=True, 
                        type="primary" if st.session_state.selected_list == default_name else "secondary"):
                st.session_state.selected_list = default_name
                st.session_state.selected_task = None
                st.rerun()
        
        st.divider()
        
        # Custom lists with delete button
        for list_id, name, color, icon in lists:
            if name not in ["My Day", "Important", "Planned", "Tasks"]:
                cols = st.columns([8, 2])
                with cols[0]:
                    if st.button(name, use_container_width=True, 
                                key=f"listbtn_{list_id}",
                                type="primary" if st.session_state.selected_list == list_id else "secondary"):
                        st.session_state.selected_list = list_id
                        st.session_state.selected_task = None
                        st.rerun()
                with cols[1]:
                    if st.button("🗑️", key=f"dellist_{list_id}", use_container_width=True):
                        if db.delete_list(list_id):
                            if st.session_state.selected_list == list_id:
                                st.session_state.selected_list = None
                            st.success(f"List '{name}' deleted.")
                            st.rerun()
        
        # Add new list
        with st.expander("+ New List"):
            with st.form("new_list_form"):
                new_list_name = st.text_input("List name", key="new_list_name_input")
                submit = st.form_submit_button("Create")
                if submit and new_list_name:
                    db.create_list(st.session_state.user_id, new_list_name)
                    # Clear the form by rerunning
                    st.rerun()
        
        st.divider()
        
        # User profile section
        with st.expander("👤 Profile"):
            st.write(f"**Username:** {st.session_state.username}")
            if st.button("Change Password"):
                st.session_state.show_change_password = True
                st.rerun()
        
        # Logout button
        if st.button("Logout"):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
    
    # Handle change password modal
    if st.session_state.get('show_change_password'):
        show_change_password_modal(db)
    
    # Main content area
    col1, col2 = st.columns([3, 2])
    
    with col1:
        if st.session_state.selected_list:
            show_task_list(db)
    
    with col2:
        if st.session_state.selected_task:
            show_task_detail(db)
        elif st.session_state.show_task_modal:
            show_task_creation_modal(db)

def show_change_password_modal(db: DatabaseManager):
    """Show change password modal"""
    st.subheader("Change Password")
    
    current_password = st.text_input("Current Password", type="password")
    new_password = st.text_input("New Password", type="password", key="change_new_password")
    confirm_password = st.text_input("Confirm New Password", type="password")
    
    # Live password validation (outside form)
    validation_result = None
    if new_password:
        validation_result = show_live_password_validator(new_password, "change")
    
    with st.form("change_password_form"):
        col1, col2 = st.columns([1, 1])
        
        with col1:
            submit = st.form_submit_button("Change Password", type="primary")
        
        with col2:
            cancel = st.form_submit_button("Cancel")
        
        if submit:
            if not current_password or not new_password or not confirm_password:
                st.error("Please fill in all fields")
            elif new_password != confirm_password:
                st.error("New passwords don't match")
            elif new_password and 'validation_result' in locals() and not validation_result['is_valid']:
                st.error("Password does not meet strength requirements")
            else:
                # Verify current password
                conn = create_connection()
                try:
                    c = conn.cursor()
                    c.execute('''SELECT password FROM users WHERE id = ?''', (st.session_state.user_id,))
                    result = c.fetchone()
                    if result and check_password(current_password, result[0]):
                        # Update password
                        hashed_pw = hash_password(new_password)
                        c.execute('''UPDATE users SET password = ? WHERE id = ?''', 
                                  (hashed_pw, st.session_state.user_id))
                        conn.commit()
                        st.success("Password changed successfully!")
                        st.session_state.show_change_password = False
                        st.rerun()
                    else:
                        st.error("Current password is incorrect")
                except Error as e:
                    st.error(f"Error changing password: {e}")
                finally:
                    conn.close()
        
        if cancel:
            st.session_state.show_change_password = False
            st.rerun()

def show_task_list(db: DatabaseManager):
    # Get the list name for custom lists
    list_id = st.session_state.selected_list
    list_name = list_id
    if list_id not in ["My Day", "Important", "Planned", "Tasks"]:
        # Fetch the name from the DB
        lists = db.get_lists(st.session_state.user_id)
        for l_id, name, color, icon in lists:
            if l_id == list_id:
                list_name = name
                break
    else:
        list_name = list_id
    st.header(list_name)
    
    # Get all tasks for the selected list
    if st.session_state.selected_list == "My Day":
        tasks = db.get_my_day_tasks(st.session_state.user_id)
    elif st.session_state.selected_list == "Important":
        tasks = db.get_important_tasks(st.session_state.user_id)
    elif st.session_state.selected_list == "Planned":
        tasks = db.get_planned_tasks(st.session_state.user_id)
    elif st.session_state.selected_list == "Tasks":
        tasks = db.get_all_tasks(st.session_state.user_id)
    else:
        tasks = db.get_tasks(st.session_state.user_id, st.session_state.selected_list, include_completed=True)

    # Separate active and completed tasks
    active_tasks = [t for t in tasks if not t[5]]
    completed_tasks = [t for t in tasks if t[5]]

    # Add task button
    if st.button("+ Add Task"):
        st.session_state.show_task_modal = True
        st.session_state.selected_task = None
        st.rerun()

    # Show active tasks with FIXED layout
    for task in active_tasks:
        task_id, title, description, due_date, reminder, is_completed, is_important, created_at = task
        
        # Use a proper container with columns that don't overflow
        container = st.container(border=True)
        with container:
            col1, col2, col3 = st.columns([1, 8, 1])
            
            # Checkbox column
            with col1:
                st.checkbox(
                    "Complete", 
                    value=is_completed, 
                    key=f"complete_{task_id}",
                    on_change=complete_task_and_flag, 
                    args=(db, task_id, not is_completed),
                    label_visibility="collapsed"
                )
            
            # Task content column
            with col2:
                if st.button(
                    title,
                    key=f"task_{task_id}",
                    help="Click to view details",
                    use_container_width=True
                ):
                    st.session_state.selected_task = task_id
                    st.session_state.show_task_modal = False
                    st.rerun()
                
                if description:
                    st.caption(description[:100] + "..." if len(description) > 100 else description)
                
                if due_date:
                    due_date_obj = datetime.fromisoformat(due_date)
                    st.caption(f"Due {due_date_obj.strftime('%b %d, %Y')}")
            
            # Star button column - properly contained
            with col3:
                star_icon = "⭐" if is_important else "☆"
                if st.button(
                    star_icon,
                    key=f"star_{task_id}",
                    help="Mark as important",
                    use_container_width=True
                ):
                    db.toggle_task_importance(task_id, not is_important)
                    st.rerun()

    # Show completed tasks in an expander with FIXED layout
    if completed_tasks:
        with st.expander(f"Completed ({len(completed_tasks)})"):
            for task in completed_tasks:
                task_id, title, description, due_date, reminder, is_completed, is_important, created_at = task
                
                container = st.container(border=True)
                with container:
                    col1, col2, col3 = st.columns([1, 8, 1])
                    
                    with col1:
                        st.checkbox(
                            "Complete", 
                            value=is_completed, 
                            key=f"complete_{task_id}_completed",
                            on_change=complete_task_and_flag, 
                            args=(db, task_id, not is_completed),
                            label_visibility="collapsed"
                        )
                    
                    with col2:
                        st.markdown(f"~~{title}~~")
                        if due_date:
                            due_date_obj = datetime.fromisoformat(due_date)
                            st.caption(f"Due {due_date_obj.strftime('%b %d, %Y')}")
                    
                    with col3:
                        star_icon = "⭐" if is_important else "☆"
                        if st.button(
                            star_icon,
                            key=f"star_{task_id}_completed",
                            help="Mark as important",
                            use_container_width=True
                        ):
                            db.toggle_task_importance(task_id, not is_important)
                            st.rerun()

    if not active_tasks and not completed_tasks:
        st.info("No tasks yet. Click 'Add Task' to get started!")

def show_task_detail(db: DatabaseManager):
    """Show detailed view of a selected task"""
    if not st.session_state.selected_task:
        return
    
    # Get task details from database
    try:
        conn = create_connection()
        c = conn.cursor()
        c.execute('''SELECT id, title, description, due_date, reminder, 
                             is_completed, is_important, list_id
                      FROM tasks 
                      WHERE id = ?''', 
                  (st.session_state.selected_task,))
        task = c.fetchone()
        
        if not task:
            st.error("Task not found")
            return
        
        task_id, title, description, due_date, reminder, is_completed, is_important, list_id = task
        
        # Task detail view
        st.header("Task Details")
        
        # Back button
        if st.button("← Back"):
            st.session_state.selected_task = None
            st.rerun()
        
        # Task title
        new_title = st.text_input("Title", value=title, key=f"title_{task_id}")
        
        # Task description
        new_description = st.text_area("Description", value=description or "", 
                                     key=f"desc_{task_id}")
        
        # Due date
        due_date_val = None
        if due_date:
            try:
                due_date_val = datetime.fromisoformat(due_date).date()
            except Exception:
                due_date_val = None
        new_due_date = st.date_input("Due Date", value=due_date_val, key=f"due_{task_id}")
        
        # Reminder
        reminder_val = None
        if reminder:
            try:
                reminder_val = datetime.fromisoformat(reminder).time()
            except Exception:
                reminder_val = None
        new_reminder = st.time_input("Reminder", value=reminder_val, key=f"reminder_{task_id}")
        
        # Important toggle
        new_important = st.toggle("Important", value=is_important, key=f"important_{task_id}")
        
        # Save button
        if st.button("Save Changes"):
            try:
                c.execute('''UPDATE tasks 
                             SET title = ?, description = ?, due_date = ?, reminder = ?, 
                                 is_important = ?, updated_at = ?
                             WHERE id = ?''', 
                          (new_title, new_description, 
                           datetime.combine(new_due_date, datetime.min.time()).isoformat() if new_due_date else None,
                           datetime.combine(new_due_date or datetime.now().date(), new_reminder).isoformat() if new_reminder else None,
                           new_important, datetime.now(pytz.utc), task_id))
                conn.commit()
                st.success("Task updated successfully!")
            except Error as e:
                st.error(f"Error updating task: {e}")
        
        # Add to My Day button
        if st.session_state.selected_list != "My Day":
            if st.button("Add to My Day"):
                if db.add_to_my_day(st.session_state.user_id, task_id):
                    st.success("Added to My Day!")
                else:
                    st.error("Failed to add to My Day")
        
        # Delete button
        if st.button("Delete Task", type="primary"):
            if db.delete_task(task_id):
                st.session_state.selected_task = None
                st.success("Task deleted successfully!")
                st.rerun()
            else:
                st.error("Failed to delete task")
    
    except Error as e:
        st.error(f"Error loading task details: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def show_task_creation_modal(db: DatabaseManager):
    """Show modal for creating a new task with enhanced validation"""
    st.header("Add New Task")
    
    # Back button
    if st.button("← Back"):
        st.session_state.show_task_modal = False
        st.rerun()
    
    with st.form("new_task_form"):
        title = st.text_input("Task name", placeholder="What do you need to do?", max_chars=200, key="new_task_title")
        description = st.text_area("Description", max_chars=1000, key="new_task_description")
        due_date = st.date_input("Due date", key="new_task_due_date")
        reminder = st.time_input("Reminder", key="new_task_reminder")
        is_important = st.toggle("Important", key="new_task_important")
        
        # Real-time validation
        if title:
            title_error = InputValidator.validate_task_title(title)
            if title_error:
                st.error(title_error)
        
        submit = st.form_submit_button("Add Task")
        
        if submit:
            # Validate inputs
            title = InputValidator.sanitize_input(title)
            description = InputValidator.sanitize_input(description)
            
            title_error = InputValidator.validate_task_title(title)
            
            if title_error:
                st.error(title_error)
            elif not title:
                st.error("Task title is required")
            else:
                # Determine which list to add to
                if st.session_state.selected_list == "My Day":
                    # Find or create My Day list
                    conn = create_connection()
                    try:
                        c = conn.cursor()
                        c.execute('''SELECT id FROM lists 
                                     WHERE user_id = ? AND name = 'My Day' ''', 
                                  (st.session_state.user_id,))
                        my_day_list = c.fetchone()
                        if not my_day_list:
                            db.create_list(st.session_state.user_id, "My Day", "#0078d7", "sun")
                            c.execute('''SELECT id FROM lists 
                                         WHERE user_id = ? AND name = 'My Day' ''', 
                                      (st.session_state.user_id,))
                            my_day_list = c.fetchone()
                        list_id = my_day_list[0]
                    except Error as e:
                        st.error(f"Error adding to My Day: {e}")
                        log_error(f"Error adding to My Day: {e}")
                    finally:
                        conn.close()
                elif st.session_state.selected_list in ["Important", "Planned", "Tasks"]:
                    # These are smart lists, so we'll add to the default "Tasks" list
                    conn = create_connection()
                    try:
                        c = conn.cursor()
                        c.execute('''SELECT id FROM lists 
                                     WHERE user_id = ? AND name = 'Tasks' ''', 
                                  (st.session_state.user_id,))
                        tasks_list = c.fetchone()
                        if not tasks_list:
                            db.create_list(st.session_state.user_id, "Tasks", "#737373", "home")
                            c.execute('''SELECT id FROM lists 
                                         WHERE user_id = ? AND name = 'Tasks' ''', 
                                      (st.session_state.user_id,))
                            tasks_list = c.fetchone()
                        list_id = tasks_list[0]
                    except Error as e:
                        st.error(f"Error adding to Tasks list: {e}")
                        log_error(f"Error adding to Tasks list: {e}")
                    finally:
                        conn.close()
                else:
                    # Custom list
                    list_id = st.session_state.selected_list
                
                # Create the task
                task_id = db.create_task(
                    st.session_state.user_id,
                    list_id,
                    title,
                    description,
                    datetime.combine(due_date, datetime.min.time()) if due_date else None,
                    datetime.combine(due_date or datetime.now().date(), reminder) if reminder else None,
                    is_important
                )
                
                if task_id:
                    st.session_state.show_task_modal = False
                    st.success("Task created successfully!")
                    st.rerun()
                else:
                    st.error("Failed to create task")

def complete_task_and_flag(db: DatabaseManager, task_id: str, is_completed: bool):
    """Helper function to handle task completion with session state flag"""
    if db.update_task_completion(task_id, is_completed):
        # Set a flag to indicate task was updated
        st.session_state.task_updated = True



def main():
    """Main application entry point"""
    # Set page config
    st.set_page_config(
        page_title="FreeToDo - Enhanced Task Manager",
        page_icon="✅",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Initialize database
    initialize_database()
    
    # Initialize database manager
    db = DatabaseManager()
    
    # Custom CSS for better styling
    st.markdown("""
    <style>
    .stButton > button {
        width: 100%;
        border-radius: 20px;
    }
    .task-container {
        padding: 10px;
        margin: 5px 0;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
    }
    .task-title {
        font-weight: 600;
        font-size: 16px;
    }
    .task-due {
        color: #666;
        font-size: 12px;
    }
    .important-star {
        color: #ffd700;
        font-size: 18px;
    }
    .sidebar .stButton > button {
        text-align: left;
        padding-left: 20px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # Check if user is logged in
    if 'user_id' not in st.session_state:
        show_login(db)
    else:
        show_main_interface(db)

if __name__ == "__main__":
    main()