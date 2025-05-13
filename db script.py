import sqlite3
import base64


def view_hashed_passwords(db_path="secure_user_database.db"):
    """View the hashed passwords to confirm they're not stored in plaintext."""
    try:
        # Connect to the database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        print("Users in database:")
        print("-" * 80)

        # Query user data
        cursor.execute("SELECT username, salt, hashed_password FROM users")
        users = cursor.fetchall()

        if not users:
            print("No users found in the database.")
            return

        # Display each user's data
        for username, salt, hashed_password in users:
            # Convert binary data to Base64 for display
            salt_b64 = base64.b64encode(salt).decode('utf-8')
            password_b64 = base64.b64encode(hashed_password).decode('utf-8')

            print(f"Username: {username}")
            print(f"Salt (Base64): {salt_b64}")
            print(f"Hashed Password (Base64): {password_b64}")
            print("-" * 80)

    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()


if __name__ == "__main__":
    view_hashed_passwords()