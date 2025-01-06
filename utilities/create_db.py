import sqlite3
import os

def create_database():
    # Connect to SQLite database (it will create the file if it doesn't exist)
    db_path = os.path.join(os.getcwd(), 'sireapp.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create Incident table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Incident (
            ID TEXT PRIMARY KEY,
            Title TEXT NOT NULL,
            Description TEXT,
            Category TEXT,
            Severity TEXT,
            Status TEXT DEFAULT "New",
            Assigned_To TEXT,
            Reporter TEXT NOT NULL,
            Created_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            Updated_At TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create User table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS User (
            ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            First_Name TEXT NOT NULL,
            Last_Name TEXT NOT NULL,
            Email TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            Role TEXT,
            Is_Admin BOOLEAN DEFAULT 0,
            Is_Manager BOOLEAN DEFAULT 0,
            Is_Responder BOOLEAN DEFAULT 0,
            Mfa_Secret TEXT,
            Mfa_Setup_Completed INTEGER DEFAULT 0
        )
    ''')

    # Commit changes and close the connection
    conn.commit()
    conn.close()
    print("Database and tables created successfully.")

# Run the function to create the database and tables
if __name__ == "__main__":
    create_database()