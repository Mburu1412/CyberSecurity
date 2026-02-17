"""
Name : Mburu Martin
Adm No : BSCIT-05-0167/2024
"""
import bcrypt
import re

class User:
    """
    Represents a user in the system.

    Attributes:
        username (str): The user's username.
        password_hash (bytes): The hashed password of the user.
        login_attempts (int): Number of failed login attempts.
        locked (bool):  Indicates if the account is locked.
    """
    def __init__(self, username, password_hash):
        """
        Initializes a User object.

        Args:
            username (str): The username of the user.
            password_hash (bytes): The hashed password of the user.
        """
        self.username = username
        self.password_hash = password_hash
        self.login_attempts = 0  # Initialize login attempts
        self.locked = False         # Initialize locked status

    def __repr__(self):
        return f"User(username='{self.username}', locked={self.locked})"


class PasswordSecurity:
    """
    Handles password-related operations like hashing and validation.
    """

    def __init__(self):
        """
        Initializes the PasswordSecurity class.
        """
        pass  # No initialization needed

    def validate_password(self, password):
        """
        Validates the password against a strength policy.

        Args:
            password (str): The password to validate.

        Returns:
            bool: True if the password is valid, False otherwise.
        """
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
            return False

        if not re.search(r"[A-Z]", password):
            print("Password must contain at least one uppercase letter.")
            return False

        if not re.search(r"[a-z]", password):
            print("Password must contain at least one lowercase letter.")
            return False

        if not re.search(r"[0-9]", password):
            print("Password must contain at least one number.")
            return False

        return True

    def hash_password(self, password):
        """
        Hashes the password using bcrypt.

        Args:
            password (str): The password to hash.

        Returns:
            bytes: The hashed password as bytes.
        """
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return hashed_password

    def check_password(self, password, hashed_password):
        """
        Checks if the password matches the hash.

        Args:
            password (str): The password to check.
            hashed_password (bytes): The stored hashed password.

        Returns:
            bool: True if the password matches the hash, False otherwise.
        """
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


class AuthenticationSystem:
    """
    Manages user authentication, including login functionality.
    """

    def __init__(self, max_login_attempts=3):
        """
        Initializes the AuthenticationSystem.
        This simplistic implementation uses a dictionary to store users.
        A more robust implementation would use a database.
        """
        self.users = {}  # Username: User object
        self.max_login_attempts = max_login_attempts # Maximum allowed login attempts

    def register_user(self, username, password):
        """
        Registers a new user.

        Args:
            username (str): The username of the new user.
            password (str): The password of the new user.

        Returns:
            bool: True if registration was successful, False otherwise.
        """
        password_security = PasswordSecurity()
        if not password_security.validate_password(password):
            return False

        hashed_password = password_security.hash_password(password)
        user = User(username, hashed_password)
        self.users[username] = user
        print(f"User '{username}' registered successfully.")
        return True

    def login(self, username, password):
        """
        Logs in an existing user.

        Args:
            username (str): The username of the user.
            password (str): The password of the user.

        Returns:
            bool: True if login was successful, False otherwise.
        """
        if username not in self.users:
            print("Invalid username.")
            return False

        user = self.users[username]

        if user.locked:
            print(f"Account '{username}' is locked. Contact administrator.")
            return False

        password_security = PasswordSecurity()
        if password_security.check_password(password, user.password_hash):
            print("Login successful!")
            user.login_attempts = 0  # Reset login attempts on successful login
            return True
        else:
            print("Incorrect password.")
            user.login_attempts += 1
            print(f"Login attempts remaining: {self.max_login_attempts - user.login_attempts}")

            if user.login_attempts >= self.max_login_attempts:
                print(f"Account '{username}' locked due to too many failed attempts.")
                user.locked = True  # Lock the account

            return False


# Example Usage
if __name__ == "__main__":
    auth_system = AuthenticationSystem()

    while True:
        print("\nChoose an action:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            auth_system.register_user(username, password)
        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            auth_system.login(username, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")
