import sqlite3
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'change_this_to_a_secure_random_value'
DATABASE = 'membership.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def check_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

@app.context_processor
def inject_year():
    return {'current_year': datetime.now().year}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password(password, user['password_hash']):
            session['user_id'] = user['id']
            return redirect(url_for('directory'))
        error = 'Invalid credentials'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        name = request.form.get('name')
        area = request.form.get('area')
        email = request.form.get('email')
        phone = request.form.get('phone')
        council_number = request.form.get('council_number') or None
        city = request.form.get('city')
        state = request.form.get('state')
        occupation = request.form.get('occupation')
        additional_info = request.form.get('additional_info')
        password = request.form.get('password')
        if not email or not password:
            error = 'Email and password required.'
        else:
            password_hash = hash_password(password)
            try:
                conn = get_db_connection()
                conn.execute(
                    '''INSERT INTO users
                       (name, area, email, phone, council_number, city, state, occupation, additional_info, password_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (name, area, email, phone, council_number, city, state, occupation, additional_info, password_hash)
                )
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Email already registered.'
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    error = None
    if request.method == 'POST':
        name = request.form.get('name')
        area = request.form.get('area')
        email = request.form.get('email')
        phone = request.form.get('phone')
        council_number = request.form.get('council_number') or None
        city = request.form.get('city')
        state = request.form.get('state')
        occupation = request.form.get('occupation')
        additional_info = request.form.get('additional_info')
        try:
            conn.execute(
                '''UPDATE users SET name=?, area=?, email=?, phone=?, council_number=?, city=?, state=?, occupation=?, additional_info=?
                   WHERE id=?''',
                (name, area, email, phone, council_number, city, state, occupation, additional_info, user_id)
            )
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        except sqlite3.IntegrityError:
            error = 'Email already registered.'
    conn.close()
    return render_template('profile.html', user=user, error=error)

@app.route('/directory')
def directory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('directory.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)