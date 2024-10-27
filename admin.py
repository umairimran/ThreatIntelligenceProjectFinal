### THIS FUNCTION CONTAINE SOLELY THE FUNCTIONS RELATED TO ADMIN
## MAJOR FUNCTIONS:
## ADMIN CAN ADD , DELETE , UPDATE USER THINGS 
## ADMIN CAN ADD FILTERS OR UPDATE THE FILTERS OF REGISTERED USERS
## ADMIN CAN SEE ALL THE REGISTERED USERS
## ADMIN WILL HAVE A COMPLETE DETAILS OF THE VULNERABILITIES FROM DATA BASE
## ADMIN CAN WILL HAVE NUMERIC STATISTICS
import sqlite3
import random
import string

def create_database():
    """Create the SQLite database and users table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Create the users table with an email field
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            system TEXT,
            service TEXT,
            indicator TEXT
        )
    ''')
    
    print("Users table created successfully.")
    
    # Commit and close the connection
    conn.commit()
    conn.close()

def add_user(username, password, email, system, service, indicator):
    """Add a new user to the users table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Insert the user into the users table
    cursor.execute('''
        INSERT INTO users (username, password, email, system, service, indicator)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, password, email, system, service, indicator))
    
    print(f"User '{username}' added successfully.")
    
    # Commit and close the connection
    conn.commit()
    conn.close()

def retrieve_users():
    """Retrieve all users from the users table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    for user in users:
        print(user)
    
    # Close the connection
    conn.close()
    return users

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))

def create_temporary_users(n=20):
    """Create n temporary users."""
    for _ in range(n):
        username = f"user_{generate_random_string(5)}"
        password = generate_random_string(8)  # Random password
        email = f"{username}@example.com"
        system = f"System{random.randint(1, 3)}"  # Random system between System1 and System3
        service = f"Service{random.randint(1, 3)}"  # Random service between Service1 and Service3
        indicator = f"Indicator{random.randint(1, 3)}"  # Random indicator between Indicator1 and Indicator3
        add_user(username, password, email, system, service, indicator)

def delete_user(user_id):
    """Delete a user from the users table by ID."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    print(f"User with ID {user_id} deleted successfully.")
    
    # Close the connection
    conn.close()

def edit_user(user_id, username, password, email, system, service, indicator):
    """Edit an existing user's details in the users table."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        UPDATE users
        SET username = ?, password = ?, email = ?, system = ?, service = ?, indicator = ?
        WHERE id = ?
    ''', (username, password, email, system, service, indicator, user_id))
    
    conn.commit()
    print(f"User with ID {user_id} updated successfully.")
    
    # Close the connection
    conn.close()

