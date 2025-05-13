import os
import sys
import hashlib
import base64
import sqlite3
import re
import secrets
import time
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Tuple, Optional


class SecureLoginSystem:
    def __init__(self, db_path: str):
        """Initialize the secure login system with a database connection."""
        # Pepper would typically be in environment variables, not in code
        self.pepper = os.environ.get('AUTH_PEPPER', secrets.token_hex(16))

        # Create/connect to the SQLite database
        self.conn = self._create_db_connection(db_path)
        self.cursor = self.conn.cursor()

        # Create necessary tables if they don't exist
        self._initialize_database()

        # Login attempt tracking for rate limiting
        self.login_attempts = {}

        # Session tokens (would use a proper session manager in production)
        self.active_sessions = {}

    def _create_db_connection(self, db_path: str) -> sqlite3.Connection:
        """Create a secure connection to the SQLite database."""
        try:
            # Enable WAL mode for better concurrency and durability
            conn = sqlite3.connect(db_path, isolation_level=None)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            return conn
        except sqlite3.Error as e:
            print(f"Database connection error: {e}")
            sys.exit(1)

    def _initialize_database(self):
        """Set up the database schema."""
        try:
            # Users table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                hashed_password BLOB NOT NULL,
                email TEXT UNIQUE,
                failed_attempts INTEGER DEFAULT 0,
                last_attempt TIMESTAMP,
                account_locked BOOLEAN DEFAULT 0,
                password_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

            # Audit log table
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
            ''')

            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            self.conn.rollback()
            sys.exit(1)

    def _validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Check if the password meets security requirements."""
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"

        # Check for complexity requirements
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"

        # Check against common password lists (simplified)
        common_passwords = ["password123", "qwerty12345", "admin12345"]
        if password.lower() in common_passwords:
            return False, "Password is too common, please choose a different one"

        return True, "Password meets requirements"

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        """Hash a password using PBKDF2 with HMAC-SHA256."""
        password_bytes = password.encode('utf-8')

        # Add pepper
        password_bytes = password_bytes + self.pepper.encode('utf-8')

        # Use PBKDF2 with 310,000 iterations (current NIST recommendation)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt,
            iterations=310000,
            dklen=32
        )

        return key

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Compare two byte strings in constant time to prevent timing attacks."""
        if len(a) != len(b):
            return False

        result = 0
        for x, y in zip(a, b):
            result |= x ^ y

        return result == 0

    def _check_rate_limit(self, username: str, ip_address: str = "unknown") -> bool:
        """Implement rate limiting to prevent brute force attacks."""
        current_time = time.time()

        # Track by IP and username
        ip_key = f"ip:{ip_address}"
        user_key = f"user:{username}"

        for key in [ip_key, user_key]:
            if key in self.login_attempts:
                attempts, timestamp = self.login_attempts[key]

                # Reset attempts after 15 minutes
                if current_time - timestamp > 900:  # 15 minutes
                    self.login_attempts[key] = (1, current_time)
                else:
                    # Implement exponential backoff
                    if attempts >= 5:
                        return False

                    self.login_attempts[key] = (attempts + 1, current_time)
            else:
                self.login_attempts[key] = (1, current_time)

        return True

    def _log_activity(self, user_id: Optional[int], action: str, ip_address: str = "unknown",
                      user_agent: str = "unknown"):
        """Log user activity for audit purposes."""
        try:
            self.cursor.execute(
                "INSERT INTO audit_log (user_id, action, ip_address, user_agent) VALUES (?, ?, ?, ?)",
                (user_id, action, ip_address, user_agent)
            )
            self.conn.commit()
        except sqlite3.Error as e:
            print(f"Audit logging error: {e}")
            self.conn.rollback()

    def register_user(self, username: str, password: str, email: str = None) -> Tuple[bool, str]:
        """Register a new user with a securely hashed password."""
        try:
            # Sanitize inputs (basic, would use prepared statements in production)
            if not username or not password:
                return False, "Username and password are required"

            if not re.match(r'^[a-zA-Z0-9_-]{3,30}$', username):
                return False, "Username must be 3-30 characters and contain only letters, numbers, underscores, and hyphens"

            # Validate password strength
            is_strong, message = self._validate_password_strength(password)
            if not is_strong:
                return False, message

            # Generate a cryptographically secure random salt
            salt = os.urandom(32)

            # Hash the password with the salt
            hashed_password = self._hash_password(password, salt)

            # Store in database with prepared statement (prevents SQL injection)
            self.cursor.execute(
                "INSERT INTO users (username, salt, hashed_password, email) VALUES (?, ?, ?, ?)",
                (username, salt, hashed_password, email)
            )
            self.conn.commit()

            # Log the activity
            user_id = self.cursor.lastrowid
            self._log_activity(user_id, "user_registered")

            return True, "User registered successfully"

        except sqlite3.IntegrityError as e:
            # Check specific constraint violation
            if "UNIQUE constraint failed: users.username" in str(e):
                return False, "Username already exists"
            elif "UNIQUE constraint failed: users.email" in str(e):
                return False, "Email already registered"
            else:
                return False, "Registration failed due to database constraint"
        except Exception as e:
            self.conn.rollback()
            return False, f"Registration failed: {str(e)}"

    def authenticate_user(self, username: str, password: str, ip_address: str = "unknown") -> Tuple[
        bool, str, Optional[str]]:
        """Authenticate a user by verifying their password."""
        # Check rate limiting first
        if not self._check_rate_limit(username, ip_address):
            self._log_activity(None, f"rate_limit_exceeded:{username}", ip_address)
            return False, "Too many login attempts. Please try again later.", None

        try:
            # Query the database for the user
            self.cursor.execute(
                "SELECT user_id, salt, hashed_password, failed_attempts, account_locked FROM users WHERE username = ?",
                (username,)
            )
            result = self.cursor.fetchone()

            if not result:
                # Always perform a hash operation even if user doesn't exist
                # to prevent timing attacks
                self._hash_password(password, os.urandom(32))
                self._log_activity(None, f"failed_login:user_not_found:{username}", ip_address)
                return False, "Invalid username or password", None

            user_id, salt, stored_hash, failed_attempts, account_locked = result

            # Check if account is locked
            if account_locked:
                self._log_activity(user_id, "login_attempt_on_locked_account", ip_address)
                return False, "Account is locked. Please contact administrator.", None

            # Hash the provided password with the stored salt
            calculated_hash = self._hash_password(password, salt)

            # Verify the password
            if self._constant_time_compare(stored_hash, calculated_hash):
                # Reset failed attempts on success
                self.cursor.execute(
                    "UPDATE users SET failed_attempts = 0, last_attempt = CURRENT_TIMESTAMP WHERE user_id = ?",
                    (user_id,)
                )

                # Generate a session token (in production, use a proper session management system)
                session_token = secrets.token_hex(32)
                self.active_sessions[session_token] = {
                    "user_id": user_id,
                    "username": username,
                    "created": datetime.now(),
                    "expires": datetime.now() + timedelta(hours=1)
                }

                self._log_activity(user_id, "successful_login", ip_address)
                self.conn.commit()
                return True, "Authentication successful", session_token

            # Increment failed attempts
            new_failed_attempts = failed_attempts + 1
            lock_account = new_failed_attempts >= 5

            self.cursor.execute(
                "UPDATE users SET failed_attempts = ?, account_locked = ?, last_attempt = CURRENT_TIMESTAMP WHERE user_id = ?",
                (new_failed_attempts, lock_account, user_id)
            )

            self._log_activity(
                user_id,
                f"failed_login:wrong_password:{new_failed_attempts}",
                ip_address
            )

            self.conn.commit()

            if lock_account:
                return False, "Account has been locked due to too many failed attempts", None
            else:
                return False, "Invalid username or password", None

        except Exception as e:
            self.conn.rollback()
            self._log_activity(None, f"login_error:{str(e)}", ip_address)
            return False, "An error occurred during authentication", None

    def change_password(self, session_token: str, current_password: str, new_password: str) -> Tuple[bool, str]:
        """Allow users to change their password after verifying the current one."""
        if session_token not in self.active_sessions:
            return False, "Not authenticated"

        session = self.active_sessions[session_token]
        if datetime.now() > session["expires"]:
            del self.active_sessions[session_token]
            return False, "Session expired"

        user_id = session["user_id"]
        username = session["username"]

        try:
            # Get current password info
            self.cursor.execute(
                "SELECT salt, hashed_password FROM users WHERE user_id = ?",
                (user_id,)
            )
            result = self.cursor.fetchone()

            if not result:
                return False, "User not found"

            salt, stored_hash = result

            # Verify current password
            calculated_hash = self._hash_password(current_password, salt)
            if not self._constant_time_compare(stored_hash, calculated_hash):
                self._log_activity(user_id, "failed_password_change:wrong_current_password")
                return False, "Current password is incorrect"

            # Validate new password
            is_strong, message = self._validate_password_strength(new_password)
            if not is_strong:
                self._log_activity(user_id, "failed_password_change:weak_password")
                return False, message

            # Check if new password is the same as current
            if current_password == new_password:
                self._log_activity(user_id, "failed_password_change:same_password")
                return False, "New password must be different from current password"

            # Generate a new salt
            new_salt = os.urandom(32)

            # Hash the new password
            new_hashed_password = self._hash_password(new_password, new_salt)

            # Update the stored information
            self.cursor.execute(
                "UPDATE users SET salt = ?, hashed_password = ?, password_changed = CURRENT_TIMESTAMP WHERE user_id = ?",
                (new_salt, new_hashed_password, user_id)
            )

            self._log_activity(user_id, "password_changed")
            self.conn.commit()

            return True, "Password changed successfully"

        except Exception as e:
            self.conn.rollback()
            self._log_activity(user_id, f"password_change_error:{str(e)}")
            return False, f"Failed to change password: {str(e)}"

    def get_password_database_path(self) -> str:
        """Return the path to the password database file."""
        return self.conn.execute("PRAGMA database_list").fetchone()[2]

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()


class LoginGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Login System")
        self.master.geometry("400x500")
        self.master.resizable(False, False)

        # Set theme
        style = ttk.Style()
        style.theme_use('clam')

        # Initialize the login system
        self.db_path = "secure_user_database.db"
        self.login_system = SecureLoginSystem(self.db_path)

        # Session management
        self.current_session = None

        # Create frames
        self.login_frame = ttk.Frame(self.master, padding=20)
        self.register_frame = ttk.Frame(self.master, padding=20)
        self.main_frame = ttk.Frame(self.master, padding=20)
        self.change_password_frame = ttk.Frame(self.master, padding=20)

        # Initialize widgets
        self._create_login_widgets()
        self._create_register_widgets()
        self._create_main_widgets()
        self._create_change_password_widgets()

        # Show login frame initially
        self.show_login_frame()

    def _create_login_widgets(self):
        # Title
        ttk.Label(self.login_frame, text="Secure Login", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2,
                                                                                          pady=20)

        # Username
        ttk.Label(self.login_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.login_username = ttk.Entry(self.login_frame, width=30)
        self.login_username.grid(row=1, column=1, pady=5)

        # Password
        ttk.Label(self.login_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.login_password = ttk.Entry(self.login_frame, width=30, show="•")
        self.login_password.grid(row=2, column=1, pady=5)

        # Login button
        self.login_button = ttk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=3, column=0, columnspan=2, pady=20)

        # Register link
        self.register_link = ttk.Button(self.login_frame, text="Create an account", style="Link.TButton",
                                        command=self.show_register_frame)
        self.register_link.grid(row=4, column=0, columnspan=2)

        # Status label
        self.login_status = ttk.Label(self.login_frame, text="", foreground="red")
        self.login_status.grid(row=5, column=0, columnspan=2, pady=10)

    def _create_register_widgets(self):
        # Title
        ttk.Label(self.register_frame, text="Create Account", font=("Arial", 16, "bold")).grid(row=0, column=0,
                                                                                               columnspan=2, pady=20)

        # Username
        ttk.Label(self.register_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=5)
        self.register_username = ttk.Entry(self.register_frame, width=30)
        self.register_username.grid(row=1, column=1, pady=5)

        # Email
        ttk.Label(self.register_frame, text="Email:").grid(row=2, column=0, sticky="w", pady=5)
        self.register_email = ttk.Entry(self.register_frame, width=30)
        self.register_email.grid(row=2, column=1, pady=5)

        # Password
        ttk.Label(self.register_frame, text="Password:").grid(row=3, column=0, sticky="w", pady=5)
        self.register_password = ttk.Entry(self.register_frame, width=30, show="•")
        self.register_password.grid(row=3, column=1, pady=5)

        # Confirm Password
        ttk.Label(self.register_frame, text="Confirm Password:").grid(row=4, column=0, sticky="w", pady=5)
        self.register_confirm_password = ttk.Entry(self.register_frame, width=30, show="•")
        self.register_confirm_password.grid(row=4, column=1, pady=5)

        # Register button
        self.register_button = ttk.Button(self.register_frame, text="Register", command=self.register)
        self.register_button.grid(row=5, column=0, columnspan=2, pady=20)

        # Login link
        self.login_link = ttk.Button(self.register_frame, text="Already have an account? Login", style="Link.TButton",
                                     command=self.show_login_frame)
        self.login_link.grid(row=6, column=0, columnspan=2)

        # Status label
        self.register_status = ttk.Label(self.register_frame, text="", foreground="red")
        self.register_status.grid(row=7, column=0, columnspan=2, pady=10)

        # Password requirements
        reqs = "Password must have at least:\n- 12 characters\n- 1 uppercase letter\n- 1 lowercase letter\n- 1 digit\n- 1 special character"
        ttk.Label(self.register_frame, text=reqs, foreground="gray").grid(row=8, column=0, columnspan=2, pady=10)

    def _create_main_widgets(self):
        # Title
        ttk.Label(self.main_frame, text="Welcome", font=("Arial", 16, "bold")).grid(row=0, column=0, columnspan=2,
                                                                                    pady=20)

        self.welcome_label = ttk.Label(self.main_frame, text="")
        self.welcome_label.grid(row=1, column=0, columnspan=2, pady=10)

        # Change password button
        self.change_pwd_button = ttk.Button(self.main_frame, text="Change Password",
                                            command=self.show_change_password_frame)
        self.change_pwd_button.grid(row=2, column=0, columnspan=2, pady=10)

        # View database button
        self.view_db_button = ttk.Button(self.main_frame, text="View Database Location",
                                         command=self.view_database_location)
        self.view_db_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Logout button
        self.logout_button = ttk.Button(self.main_frame, text="Logout", command=self.logout)
        self.logout_button.grid(row=4, column=0, columnspan=2, pady=20)

    def _create_change_password_widgets(self):
        # Title
        ttk.Label(self.change_password_frame, text="Change Password", font=("Arial", 16, "bold")).grid(row=0, column=0,
                                                                                                       columnspan=2,
                                                                                                       pady=20)

        # Current Password
        ttk.Label(self.change_password_frame, text="Current Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.current_password = ttk.Entry(self.change_password_frame, width=30, show="•")
        self.current_password.grid(row=1, column=1, pady=5)

        # New Password
        ttk.Label(self.change_password_frame, text="New Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.new_password = ttk.Entry(self.change_password_frame, width=30, show="•")
        self.new_password.grid(row=2, column=1, pady=5)

        # Confirm New Password
        ttk.Label(self.change_password_frame, text="Confirm New Password:").grid(row=3, column=0, sticky="w", pady=5)
        self.confirm_new_password = ttk.Entry(self.change_password_frame, width=30, show="•")
        self.confirm_new_password.grid(row=3, column=1, pady=5)

        # Submit button
        self.submit_pwd_button = ttk.Button(self.change_password_frame, text="Submit", command=self.change_password)
        self.submit_pwd_button.grid(row=4, column=0, columnspan=2, pady=20)

        # Back button
        self.back_button = ttk.Button(self.change_password_frame, text="Back", command=self.show_main_frame)
        self.back_button.grid(row=5, column=0, columnspan=2)

        # Status label
        self.change_pwd_status = ttk.Label(self.change_password_frame, text="", foreground="red")
        self.change_pwd_status.grid(row=6, column=0, columnspan=2, pady=10)

        # Password requirements
        reqs = "Password must have at least:\n- 12 characters\n- 1 uppercase letter\n- 1 lowercase letter\n- 1 digit\n- 1 special character"
        ttk.Label(self.change_password_frame, text=reqs, foreground="gray").grid(row=7, column=0, columnspan=2, pady=10)

    def show_login_frame(self):
        self.register_frame.grid_forget()
        self.main_frame.grid_forget()
        self.change_password_frame.grid_forget()
        self.login_frame.grid(row=0, column=0)
        self.login_status.config(text="")
        self.login_username.focus()

    def show_register_frame(self):
        self.login_frame.grid_forget()
        self.main_frame.grid_forget()
        self.change_password_frame.grid_forget()
        self.register_frame.grid(row=0, column=0)
        self.register_status.config(text="")
        self.register_username.focus()

    def show_main_frame(self):
        self.login_frame.grid_forget()
        self.register_frame.grid_forget()
        self.change_password_frame.grid_forget()
        self.main_frame.grid(row=0, column=0)

    def show_change_password_frame(self):
        self.login_frame.grid_forget()
        self.register_frame.grid_forget()
        self.main_frame.grid_forget()
        self.change_password_frame.grid(row=0, column=0)
        self.change_pwd_status.config(text="")
        self.current_password.focus()

    def login(self):
        username = self.login_username.get()
        password = self.login_password.get()

        if not username or not password:
            self.login_status.config(text="Please enter both username and password")
            return

        success, message, session_token = self.login_system.authenticate_user(username, password)

        if success:
            self.current_session = session_token
            self.welcome_label.config(text=f"Welcome, {username}!")
            self.login_password.delete(0, tk.END)
            self.show_main_frame()
        else:
            self.login_status.config(text=message)

    def register(self):
        username = self.register_username.get()
        email = self.register_email.get()
        password = self.register_password.get()
        confirm_password = self.register_confirm_password.get()

        if not username or not password or not confirm_password:
            self.register_status.config(text="Please fill out all required fields")
            return

        if password != confirm_password:
            self.register_status.config(text="Passwords do not match")
            return

        # Basic email validation
        if email and not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            self.register_status.config(text="Invalid email format")
            return

        success, message = self.login_system.register_user(username, password, email)

        if success:
            messagebox.showinfo("Registration Successful", "Account created successfully! You can now login.")
            self.register_username.delete(0, tk.END)
            self.register_email.delete(0, tk.END)
            self.register_password.delete(0, tk.END)
            self.register_confirm_password.delete(0, tk.END)
            self.show_login_frame()
        else:
            self.register_status.config(text=message)

    def change_password(self):
        current_pwd = self.current_password.get()
        new_pwd = self.new_password.get()
        confirm_new_pwd = self.confirm_new_password.get()

        if not current_pwd or not new_pwd or not confirm_new_pwd:
            self.change_pwd_status.config(text="Please fill out all fields")
            return

        if new_pwd != confirm_new_pwd:
            self.change_pwd_status.config(text="New passwords do not match")
            return

        success, message = self.login_system.change_password(self.current_session, current_pwd, new_pwd)

        if success:
            messagebox.showinfo("Success", "Password changed successfully")
            self.current_password.delete(0, tk.END)
            self.new_password.delete(0, tk.END)
            self.confirm_new_password.delete(0, tk.END)
            self.show_main_frame()
        else:
            self.change_pwd_status.config(text=message)

    def logout(self):
        self.current_session = None
        self.login_username.delete(0, tk.END)
        self.show_login_frame()

    def view_database_location(self):
        db_path = self.login_system.get_password_database_path()
        messagebox.showinfo("Database Location", f"Password database is stored at:\n{db_path}")

    def on_closing(self):
        self.login_system.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = LoginGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()