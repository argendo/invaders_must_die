import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
''')

users_data = [
    ('admin', 'admin'),
    ('user', 'user'),
    # Add more users as needed
]

# Insert sample user data into the table
cursor.executemany('INSERT INTO users (username, password) VALUES (?, ?)', users_data)

# Commit the changes and close the connection
conn.commit()
conn.close()

print("SQLite database 'users.db' created with user credentials.")
