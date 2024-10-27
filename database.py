import sqlite3

def create_connection(db_file):

    """Create a database connection to the SQLite database specified by db_file.
    
    If the database file does not exist, it will be created.
    
    Args:
        db_file (str): The path to the database file.

    Returns:
        conn (sqlite3.Connection): Connection object or None if connection failed.
    """
    conn = None
    try:
        # Attempt to connect to the SQLite database, creating it if it doesn't exist
        conn = sqlite3.connect(db_file)
        print(f"Connected to '{db_file}' successfully.")
    except sqlite3.Error as e:
        # Log the error message if connection fails
        print(f"Failed to connect to '{db_file}'. Error: {e}")
    finally:
        # If a connection was made, return it; otherwise, return None
        if conn:
            return conn
        else:
            print("No connection was established.")
            return None
        
def create_table(conn, create_table_sql):

    """Create a table from the create_table_sql statement.
    
    Args:
        conn (sqlite3.Connection): Connection object.
        create_table_sql (str): A CREATE TABLE statement.

    Returns:
        None
    """
    try:
        # Create a cursor object to execute SQL commands
        c = conn.cursor()
        # Execute the CREATE TABLE statement
        c.execute(create_table_sql)
        print("Table created successfully.")
    except sqlite3.Error as e:
        # Log the error message if table creation fails
        print(f"Failed to create table. Error: {e}")

def create_indicators_table(conn):
    
        """Create the indicators table.
        
        Args:
            conn (sqlite3.Connection): Connection object.
    
        Returns:
            None
        """
        # Define the CREATE TABLE statement for the indicators table
        create_table_sql = """CREATE TABLE IF NOT EXISTS indicators (
                                id INTEGER PRIMARY KEY,
                                indicator TEXT NOT NULL,
                                type TEXT NOT NULL,
                                created TEXT NOT NULL,
                                content TEXT,
                                title TEXT,
                                description TEXT,
                                expiration TEXT,
                                is_active INTEGER NOT NULL,
                                role TEXT
                            );"""
        # Create the indicators table
        create_table(conn, create_table_sql)

def insert_indicator(conn, indicator_data):
    """
    Insert a new indicator into the indicators table.

    Args:
        conn: SQLite database connection object.
        indicator_data (dict): Dictionary containing the indicator details.
    
    Returns:
        bool: True if the insert was successful, False otherwise.
    """
    # SQL statement to insert an indicator
    sql_insert_indicator = """
        INSERT INTO indicators (id, indicator, type, created, content, title, description, expiration, is_active, role)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    """

    try:
        # Create a cursor object using the connection
        cursor = conn.cursor()

        # Execute the insert statement with data
        cursor.execute(sql_insert_indicator, (
            indicator_data['id'],
            indicator_data['indicator'],
            indicator_data['type'],
            indicator_data['created'],
            indicator_data['content'],
            indicator_data['title'],
            indicator_data['description'],
            indicator_data['expiration'],
            indicator_data['is_active'],
            indicator_data['role']
        ))

        # Commit the transaction
        conn.commit()
        print("Indicator inserted successfully:", indicator_data)
        return True  # Indicate success

    except sqlite3.IntegrityError as e:
        print(f"Error inserting indicator: IntegrityError - {e}")
    except sqlite3.Error as e:
        print(f"Error inserting indicator: SQLiteError - {e}")
    except Exception as e:
        print(f"Unexpected error occurred while inserting indicator: {e}")

    return False  # Indicate failure

