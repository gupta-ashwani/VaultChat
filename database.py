import sqlite3

DB_FILE = 'secure_messaging.db'

def get_connection():
    return sqlite3.connect(DB_FILE)

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Drop old tables to apply schema migration (fine for dev)
    cursor.execute('DROP TABLE IF EXISTS Messages')
    cursor.execute('DROP TABLE IF EXISTS Users')
    
    # Create Users table with friend_code
    cursor.execute('''
        CREATE TABLE Users (
            username TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            friend_code TEXT UNIQUE NOT NULL
        )
    ''')
    
    # Create Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS Messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            xml_payload TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender) REFERENCES Users (username),
            FOREIGN KEY (receiver) REFERENCES Users (username)
        )
    ''')
    
    conn.commit()
    conn.close()

import random
import string

def generate_friend_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def register_user(username, public_key):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Check if user already exists
        cursor.execute('SELECT friend_code FROM Users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            # Update key but keep friend code
            friend_code = row[0]
            cursor.execute('UPDATE Users SET public_key = ? WHERE username = ?', (public_key, username))
        else:
            # Generate new friend code and insert
            friend_code = generate_friend_code()
            cursor.execute('INSERT INTO Users (username, public_key, friend_code) VALUES (?, ?, ?)', 
                           (username, public_key, friend_code))
        conn.commit()
        return friend_code
    except Exception as e:
        print(f"Error registering user: {e}")
        return None
    finally:
        conn.close()

def get_public_key(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT public_key FROM Users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_user_by_code(friend_code):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT username, public_key FROM Users WHERE friend_code = ?', (friend_code,))
    result = cursor.fetchone()
    conn.close()
    return result # returns (username, public_key) or None

def send_message(sender, receiver, xml_payload):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO Messages (sender, receiver, xml_payload) VALUES (?, ?, ?)', (sender, receiver, xml_payload))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error saving message: {e}")
        return False
    finally:
        conn.close()

def get_messages(username):
    conn = get_connection()
    cursor = conn.cursor()
    # Fetch messages and delete them so they are only delivered once
    cursor.execute('SELECT id, sender, xml_payload, timestamp FROM Messages WHERE receiver = ? ORDER BY timestamp ASC', (username,))
    messages = cursor.fetchall()
    
    if messages:
        # Delete fetched messages to mimic real messaging app behavior (messages are removed from server once delivered)
        ids = [msg[0] for msg in messages]
        placeholders = ', '.join(['?'] * len(ids))
        cursor.execute(f'DELETE FROM Messages WHERE id IN ({placeholders})', ids)
        conn.commit()
        
    conn.close()
    return messages

if __name__ == '__main__':
    init_db()
    print("Database initialized.")
