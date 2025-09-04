# filepath: /Users/davidfarfan/Documents/GITHUB/LULAC/LULAC-DIRECTORY/init_db.py
import sqlite3

conn = sqlite3.connect('membership.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        area TEXT,
        email TEXT UNIQUE NOT NULL,
        phone TEXT,
        council_number INTEGER,
        city TEXT,
        state TEXT,
        occupation TEXT,
        additional_info TEXT,
        password_hash TEXT NOT NULL
    )
''')
conn.commit()
conn.close()
print("Database initialized with first_name and last_name.")