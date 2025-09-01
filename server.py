#!/usr/bin/env python3
"""
A simple membership portal for LULAC members.

This web application provides a minimal password‑protected portal where members
can register, sign in, update their contact details and browse a directory of
other members.  The application is deliberately implemented using only Python
standard library modules (sqlite3, http.server, http.cookies, etc.) so that it
will run in environments without external package access.  Passwords are
stored as SHA‑256 hashes for basic security.

To run the server:

    python3 server.py

Then open a browser to http://localhost:8000

Note: This server is for demonstration purposes.  For production use you
should consider using a robust framework such as Flask or Django, add proper
password hashing (with salt and a slow hashing algorithm), enable HTTPS,
validate inputs, and implement access control for administrative functions.
"""

import os
import sys
import sqlite3
import hashlib
import random
import string
import urllib.parse
import http.cookies
from datetime import datetime, timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_FILE = os.path.join(os.path.dirname(__file__), "membership.db")

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


def init_db(db_path: str = DB_FILE) -> None:
    """Create the database and tables if they do not already exist."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Create the users table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            council_number TEXT,
            city TEXT,
            state TEXT,
            phone TEXT,
            occupation TEXT,
            additional_info TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Create the sessions table
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.commit()
    conn.close()


def generate_session_id(length: int = 32) -> str:
    """Generate a random session identifier."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def hash_password(password: str) -> str:
    """Return a SHA‑256 hash of the provided password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


class MembershipHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the membership portal."""

    def do_GET(self):  # noqa: N802 (keep method name for HTTP server)
        """Handle HTTP GET requests."""
        # Route based on path
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path.startswith('/static/'):
            return self.serve_static(path)
        if path == '/':
            return self.handle_home()
        if path == '/register':
            return self.handle_register_get()
        if path == '/login':
            return self.handle_login_get()
        if path == '/logout':
            return self.handle_logout()
        if path == '/profile':
            return self.handle_profile_get()
        if path == '/directory':
            return self.handle_directory_get(parsed.query)

        # Not found
        self.send_error(HTTPStatus.NOT_FOUND, f"Unknown path {path}")

    def do_POST(self):  # noqa: N802
        """Handle HTTP POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == '/register':
            return self.handle_register_post()
        if path == '/login':
            return self.handle_login_post()
        if path == '/profile':
            return self.handle_profile_post()
        # Default: method not allowed
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, f"Cannot POST to {path}")

    # Utility methods for session and database access

    def get_db_connection(self):
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn

    def get_current_user_id(self):
        """Return the user ID associated with the current session, or None."""
        cookie_header = self.headers.get('Cookie')
        if not cookie_header:
            return None
        cookies = http.cookies.SimpleCookie(cookie_header)
        session_cookie = cookies.get('session_id')
        if not session_cookie:
            return None
        session_id = session_cookie.value
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return row['user_id']
        return None

    def set_session(self, user_id: int):
        """Create a new session for the given user ID and set cookie."""
        session_id = generate_session_id()
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, datetime('now'))",
                    (session_id, user_id))
        conn.commit()
        conn.close()
        # Set cookie
        cookie = http.cookies.SimpleCookie()
        cookie['session_id'] = session_id
        cookie['session_id']['path'] = '/'
        # HttpOnly flag helps mitigate cross‑site scripting
        cookie['session_id']['httponly'] = True
        # Set cookie to expire in 7 days
        expires = (datetime.utcnow() + timedelta(days=7)).strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        cookie['session_id']['expires'] = expires
        self.send_header('Set-Cookie', cookie.output(header='', sep=''))

    def clear_session(self):
        """Remove session for current cookie and clear cookie."""
        cookie_header = self.headers.get('Cookie')
        if cookie_header:
            cookies = http.cookies.SimpleCookie(cookie_header)
            session_cookie = cookies.get('session_id')
            if session_cookie:
                session_id = session_cookie.value
                conn = self.get_db_connection()
                cur = conn.cursor()
                cur.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
                conn.commit()
                conn.close()
        # Clear cookie client side
        cookie = http.cookies.SimpleCookie()
        cookie['session_id'] = ''
        cookie['session_id']['path'] = '/'
        cookie['session_id']['expires'] = 'Thu, 01 Jan 1970 00:00:00 GMT'
        self.send_header('Set-Cookie', cookie.output(header='', sep=''))

    # Rendering utilities

    def send_html(self, html: str, status: int = 200):
        """Send an HTML response."""
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html.encode('utf-8'))))
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def redirect(self, location: str):
        """Send a 302 redirect to the given location."""
        self.send_response(HTTPStatus.FOUND)
        self.send_header('Location', location)
        self.end_headers()

    def serve_static(self, path: str):
        """Serve static files from the static directory."""
        # Security: prevent directory traversal
        rel_path = path[len('/static/'):]  # remove prefix
        rel_path = os.path.normpath(rel_path).lstrip(os.sep)
        file_path = os.path.join(STATIC_DIR, rel_path)
        if not os.path.commonpath([os.path.abspath(file_path), STATIC_DIR]).startswith(os.path.abspath(STATIC_DIR)):
            return self.send_error(HTTPStatus.FORBIDDEN, "Forbidden")
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.send_error(HTTPStatus.NOT_FOUND, "File not found")
        # Determine content type
        ext = os.path.splitext(file_path)[1].lower()
        content_type = {
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.ico': 'image/x-icon',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
        }.get(ext, 'application/octet-stream')
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Unable to read file")

    def build_page(self, title: str, body_html: str, user_id: int | None = None) -> str:
        """Construct a full HTML page including navigation."""
        nav_links = []
        if user_id:
            nav_links.append('<a href="/directory">Directory</a>')
            nav_links.append('<a href="/profile">My Profile</a>')
            nav_links.append('<a href="/logout">Logout</a>')
        else:
            nav_links.append('<a href="/login">Login</a>')
            nav_links.append('<a href="/register">Register</a>')
        nav_html = ' | '.join(nav_links)
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
            <link rel="stylesheet" type="text/css" href="/static/style.css">
        </head>
        <body>
            <header>
                <h1>LULAC Membership Portal</h1>
                <nav>{nav_html}</nav>
            </header>
            <main>
                {body_html}
            </main>
            <footer>
                <p>&copy; {datetime.now().year} LULAC</p>
            </footer>
        </body>
        </html>
        """

    # Handlers for specific pages

    def handle_home(self):
        user_id = self.get_current_user_id()
        if user_id:
            # fetch user info
            conn = self.get_db_connection()
            cur = conn.cursor()
            cur.execute("SELECT first_name, last_name FROM users WHERE id=?", (user_id,))
            row = cur.fetchone()
            conn.close()
            name = ''
            if row:
                name_parts = [row['first_name'], row['last_name']]
                name = ' '.join(filter(None, name_parts))
            greeting = f"<p>Welcome back, {name or 'Member'}!</p>"
            greeting += "<p>Use the navigation links above to browse the member directory or update your profile.</p>"
            html = self.build_page("Home", greeting, user_id)
        else:
            body = """
            <p>Welcome to the LULAC membership portal. Please <a href="/login">log in</a>
            or <a href="/register">create an account</a> to access the member directory.</p>
            """
            html = self.build_page("Home", body, None)
        self.send_html(html)

    def handle_register_get(self):
        user_id = self.get_current_user_id()
        if user_id:
            # Already logged in; redirect to profile
            return self.redirect('/profile')
        body = """
        <h2>Create Account</h2>
        <form method="post" action="/register">
            <label>Email:<br><input type="email" name="email" required></label><br>
            <label>Password:<br><input type="password" name="password" required></label><br>
            <label>Confirm Password:<br><input type="password" name="confirm_password" required></label><br>
            <label>First Name:<br><input type="text" name="first_name"></label><br>
            <label>Last Name:<br><input type="text" name="last_name"></label><br>
            <label>Council Number:<br><input type="text" name="council_number"></label><br>
            <label>City:<br><input type="text" name="city"></label><br>
            <label>State:<br><input type="text" name="state"></label><br>
            <label>Phone:<br><input type="text" name="phone"></label><br>
            <label>Occupation:<br><input type="text" name="occupation"></label><br>
            <label>Additional Info:<br><textarea name="additional_info"></textarea></label><br>
            <input type="submit" value="Create Account">
        </form>
        """
        html = self.build_page("Register", body, None)
        self.send_html(html)

    def handle_register_post(self):
        # parse POST data
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        # Extract fields
        email = params.get('email', [''])[0].strip().lower()
        password = params.get('password', [''])[0]
        confirm_password = params.get('confirm_password', [''])[0]
        first_name = params.get('first_name', [''])[0].strip()
        last_name = params.get('last_name', [''])[0].strip()
        council_number = params.get('council_number', [''])[0].strip()
        city = params.get('city', [''])[0].strip()
        state = params.get('state', [''])[0].strip()
        phone = params.get('phone', [''])[0].strip()
        occupation = params.get('occupation', [''])[0].strip()
        additional_info = params.get('additional_info', [''])[0].strip()
        # Validate inputs
        errors = []
        if not email:
            errors.append("Email is required.")
        if not password:
            errors.append("Password is required.")
        if password != confirm_password:
            errors.append("Passwords do not match.")
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            errors.append("A user with that email already exists.")
        if errors:
            conn.close()
            body = f"<h2>Create Account</h2><p style='color:red'>{'<br>'.join(errors)}</p>"
            body += """
            <form method="post" action="/register">
                <label>Email:<br><input type="email" name="email" value="{email}" required></label><br>
                <label>Password:<br><input type="password" name="password" required></label><br>
                <label>Confirm Password:<br><input type="password" name="confirm_password" required></label><br>
                <label>First Name:<br><input type="text" name="first_name" value="{first_name}"></label><br>
                <label>Last Name:<br><input type="text" name="last_name" value="{last_name}"></label><br>
                <label>Council Number:<br><input type="text" name="council_number" value="{council_number}"></label><br>
                <label>City:<br><input type="text" name="city" value="{city}"></label><br>
                <label>State:<br><input type="text" name="state" value="{state}"></label><br>
                <label>Phone:<br><input type="text" name="phone" value="{phone}"></label><br>
                <label>Occupation:<br><input type="text" name="occupation" value="{occupation}"></label><br>
                <label>Additional Info:<br><textarea name="additional_info">{additional_info}</textarea></label><br>
                <input type="submit" value="Create Account">
            </form>
            """.format(
                email=email,
                first_name=first_name,
                last_name=last_name,
                council_number=council_number,
                city=city,
                state=state,
                phone=phone,
                occupation=occupation,
                additional_info=additional_info,
            )
            html = self.build_page("Register", body, None)
            return self.send_html(html)
        # Create user
        password_hash = hash_password(password)
        cur.execute(
            """
            INSERT INTO users (email, password_hash, first_name, last_name, council_number,
                               city, state, phone, occupation, additional_info)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (email, password_hash, first_name, last_name, council_number,
             city, state, phone, occupation, additional_info)
        )
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        # Log user in by creating session
        self.send_response(HTTPStatus.FOUND)
        self.set_session(user_id)
        self.send_header('Location', '/directory')
        self.end_headers()

    def handle_login_get(self):
        user_id = self.get_current_user_id()
        if user_id:
            return self.redirect('/directory')
        body = """
        <h2>Login</h2>
        <form method="post" action="/login">
            <label>Email:<br><input type="email" name="email" required></label><br>
            <label>Password:<br><input type="password" name="password" required></label><br>
            <input type="submit" value="Log In">
        </form>
        """
        html = self.build_page("Login", body, None)
        self.send_html(html)

    def handle_login_post(self):
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        email = params.get('email', [''])[0].strip().lower()
        password = params.get('password', [''])[0]
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        conn.close()
        error = None
        if not row:
            error = "Invalid email or password."
        else:
            stored_hash = row['password_hash']
            if stored_hash != hash_password(password):
                error = "Invalid email or password."
        if error:
            body = f"<h2>Login</h2><p style='color:red'>{error}</p>"
            body += """
            <form method="post" action="/login">
                <label>Email:<br><input type="email" name="email" value="{email}" required></label><br>
                <label>Password:<br><input type="password" name="password" required></label><br>
                <input type="submit" value="Log In">
            </form>
            """.format(email=email)
            html = self.build_page("Login", body, None)
            return self.send_html(html)
        # Credentials valid
        user_id = row['id']
        self.send_response(HTTPStatus.FOUND)
        self.set_session(user_id)
        self.send_header('Location', '/directory')
        self.end_headers()

    def handle_logout(self):
        self.send_response(HTTPStatus.FOUND)
        self.clear_session()
        self.send_header('Location', '/')
        self.end_headers()

    def handle_profile_get(self):
        user_id = self.get_current_user_id()
        if not user_id:
            return self.redirect('/login')
        # Get user info
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT email, first_name, last_name, council_number, city, state, phone, occupation, additional_info "
            "FROM users WHERE id=?",
            (user_id,)
        )
        row = cur.fetchone()
        conn.close()
        if not row:
            return self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, "User not found")
        body = f"""
        <h2>My Profile</h2>
        <form method="post" action="/profile">
            <label>Email:<br><input type="email" name="email" value="{row['email']}" required></label><br>
            <label>First Name:<br><input type="text" name="first_name" value="{row['first_name'] or ''}"></label><br>
            <label>Last Name:<br><input type="text" name="last_name" value="{row['last_name'] or ''}"></label><br>
            <label>Council Number:<br><input type="text" name="council_number" value="{row['council_number'] or ''}"></label><br>
            <label>City:<br><input type="text" name="city" value="{row['city'] or ''}"></label><br>
            <label>State:<br><input type="text" name="state" value="{row['state'] or ''}"></label><br>
            <label>Phone:<br><input type="text" name="phone" value="{row['phone'] or ''}"></label><br>
            <label>Occupation:<br><input type="text" name="occupation" value="{row['occupation'] or ''}"></label><br>
            <label>Additional Info:<br><textarea name="additional_info">{row['additional_info'] or ''}</textarea></label><br>
            <input type="submit" value="Update Profile">
        </form>
        """
        html = self.build_page("My Profile", body, user_id)
        self.send_html(html)

    def handle_profile_post(self):
        user_id = self.get_current_user_id()
        if not user_id:
            return self.redirect('/login')
        length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        email = params.get('email', [''])[0].strip().lower()
        first_name = params.get('first_name', [''])[0].strip()
        last_name = params.get('last_name', [''])[0].strip()
        council_number = params.get('council_number', [''])[0].strip()
        city = params.get('city', [''])[0].strip()
        state = params.get('state', [''])[0].strip()
        phone = params.get('phone', [''])[0].strip()
        occupation = params.get('occupation', [''])[0].strip()
        additional_info = params.get('additional_info', [''])[0].strip()
        # Update database
        conn = self.get_db_connection()
        cur = conn.cursor()
        # Check email uniqueness if changed
        cur.execute("SELECT id FROM users WHERE email=? AND id != ?", (email, user_id))
        if cur.fetchone():
            conn.close()
            body = f"<h2>My Profile</h2><p style='color:red'>Email already in use by another account.</p>"
            body += """
            <form method="post" action="/profile">
                <label>Email:<br><input type="email" name="email" value="{email}" required></label><br>
                <label>First Name:<br><input type="text" name="first_name" value="{first_name}"></label><br>
                <label>Last Name:<br><input type="text" name="last_name" value="{last_name}"></label><br>
                <label>Council Number:<br><input type="text" name="council_number" value="{council_number}"></label><br>
                <label>City:<br><input type="text" name="city" value="{city}"></label><br>
                <label>State:<br><input type="text" name="state" value="{state}"></label><br>
                <label>Phone:<br><input type="text" name="phone" value="{phone}"></label><br>
                <label>Occupation:<br><input type="text" name="occupation" value="{occupation}"></label><br>
                <label>Additional Info:<br><textarea name="additional_info">{additional_info}</textarea></label><br>
                <input type="submit" value="Update Profile">
            </form>
            """.format(
                email=email,
                first_name=first_name,
                last_name=last_name,
                council_number=council_number,
                city=city,
                state=state,
                phone=phone,
                occupation=occupation,
                additional_info=additional_info,kamila garcia zamora + 34* +kamila garcia 
            )
            html = self.build_page("My Profile", body, user_id)
            return self.send_html(html)
        cur.execute(
            """
            UPDATE users
            SET email=?, first_name=?, last_name=?, council_number=?, city=?, state=?, phone=?, occupation=?, additional_info=?
            WHERE id=?
            """,
            (
                email,
                first_name,
                last_name,
                council_number,
                city,
                state,
                phone,
                occupation,
                additional_info,
                user_id,
            ),
        )
        conn.commit()
        conn.close()
        return self.redirect('/profile')

    def handle_directory_get(self, query: str):
        user_id = self.get_current_user_id()
        if not user_id:
            return self.redirect('/login')
        # Parse filters from query string
        params = urllib.parse.parse_qs(query)
        filters = {
            'city': params.get('city', [''])[0].strip(),
            'state': params.get('state', [''])[0].strip(),
            'occupation': params.get('occupation', [''])[0].strip(),
            'council_number': params.get('council_number', [''])[0].strip(),
        }
        # Build SQL query
        sql = "SELECT first_name, last_name, email, phone, council_number, city, state, occupation, additional_info FROM users WHERE 1=1"
        values: list[str] = []
        for key, value in filters.items():
            if value:
                sql += f" AND {key} LIKE ?"
                values.append(f"%{value}%")
        sql += " ORDER BY last_name, first_name"
        conn = self.get_db_connection()
        cur = conn.cursor()
        cur.execute(sql, values)
        rows = cur.fetchall()
        conn.close()
        # Build filter form HTML
        filter_html = f"""
        <h2>Member Directory</h2>
        <form method="get" action="/directory" class="filter-form">
            <label>City:<br><input type="text" name="city" value="{filters['city']}"></label>
            <label>State:<br><input type="text" name="state" value="{filters['state']}"></label>
            <label>Occupation:<br><input type="text" name="occupation" value="{filters['occupation']}"></label>
            <label>Council Number:<br><input type="text" name="council_number" value="{filters['council_number']}"></label>
            <input type="submit" value="Filter">
            <a href="/directory">Clear</a>
        </form>
        """
        # Build table HTML
        table_rows = []
        for row in rows:
            name = ' '.join(filter(None, [row['first_name'], row['last_name']])).strip()
            email = row['email'] or ''
            phone = row['phone'] or ''
            council_number = row['council_number'] or ''
            city_val = row['city'] or ''
            state_val = row['state'] or ''
            occupation_val = row['occupation'] or ''
            additional = (row['additional_info'] or '').replace('\n', '<br>')
            table_rows.append(
                f"<tr><td>{name}</td><td>{email}</td><td>{phone}</td><td>{council_number}</td>"
                f"<td>{city_val}</td><td>{state_val}</td><td>{occupation_val}</td><td>{additional}</td></tr>"
            )
        directory_table = """
        <table class="directory">
            <thead>
                <tr>
                    <th>Name</th><th>Email</th><th>Phone</th><th>Council</th><th>City</th><th>State</th><th>Occupation</th><th>Additional Info</th>
                </tr>
            </thead>
            <tbody>
        """ + "\n".join(table_rows) + """
            </tbody>
        </table>
        """
        body = filter_html + directory_table
        html = self.build_page("Member Directory", body, user_id)
        self.send_html(html)


def run_server(port: int = 8000):
    # Ensure the database exists
    init_db()
    server_address = ('', port)
    httpd = HTTPServer(server_address, MembershipHandler)
    print(f"Serving on http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Shutting down server")
        httpd.server_close()


if __name__ == '__main__':
    run_server()