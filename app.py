import os
import hashlib
from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)
app.secret_key = 'change_this_to_a_secure_random_value'
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
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
        # LOGIN
        user = conn.execute('SELECT * FROM users WHERE email = %s', (email,)).fetchone()
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
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        area = request.form.get('area')
        email = request.form.get('email')
        phone = request.form.get('phone')
        council_number = request.form.get('council_number') or None
        city = request.form.get('city')
        state = request.form.get('state')
        occupation = request.form.get('occupation')
        additional_info = request.form.get('additional_info')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not email or not password:
            error = 'Email and password required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'
        else:
            password_hash = hash_password(password)
            try:
                conn = get_db_connection()
                # REGISTER
                conn.execute(
                    '''INSERT INTO users
                       (first_name, last_name, area, email, phone, council_number, city, state, occupation, additional_info, password_hash)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)''',
                    (first_name, last_name, area, email, phone, council_number, city, state, occupation, additional_info, password_hash)
                )
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            except psycopg2.IntegrityError:
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
    user = conn.execute('SELECT * FROM users WHERE id = %s', (user_id,)).fetchone()
    error = None
    success = None
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        area = request.form.get('area')
        email = request.form.get('email')
        phone = request.form.get('phone')
        council_number = request.form.get('council_number') or None
        city = request.form.get('city')
        state = request.form.get('state')
        occupation = request.form.get('occupation')
        additional_info = request.form.get('additional_info')

        # Cambio de contraseña
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        try:
            # PROFILE
            conn.execute(
                '''UPDATE users SET first_name=%s, last_name=%s, area=%s, email=%s, phone=%s, council_number=%s, city=%s, state=%s, occupation=%s, additional_info=%s
                   WHERE id=%s''',
                (first_name, last_name, area, email, phone, council_number, city, state, occupation, additional_info, user_id)
            )
            # Si se intenta cambiar la contraseña
            if new_password or confirm_new_password or current_password:
                if not current_password or not new_password or not confirm_new_password:
                    error = 'To change your password, fill all password fields.'
                elif not check_password(current_password, user['password_hash']):
                    error = 'Current password is incorrect.'
                elif new_password != confirm_new_password:
                    error = 'New passwords do not match.'
                else:
                    new_hash = hash_password(new_password)
                    conn.execute('UPDATE users SET password_hash=%s WHERE id=%s', (new_hash, user_id))
                    success = 'Password updated successfully.'
            conn.commit()
            user = conn.execute('SELECT * FROM users WHERE id = %s', (user_id,)).fetchone()
        except psycopg2.IntegrityError:
            error = 'Email already registered.'
    conn.close()
    return render_template('profile.html', user=user, error=error, success=success)

@app.route('/directory')
def directory():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    filter_by = request.args.get('filter_by', 'first_name')
    query = request.args.get('query', '').strip()
    allowed_filters = ['first_name', 'last_name', 'email', 'area', 'city', 'state']
    if filter_by not in allowed_filters:
        filter_by = 'first_name'
    page = int(request.args.get('page', 1))
    per_page = 10
    offset = (page - 1) * per_page

    conn = get_db_connection()
    if query:
        # DIRECTORY
        sql = f"SELECT * FROM users WHERE {filter_by} LIKE %s LIMIT %s OFFSET %s"
        users = conn.execute(sql, (f"%{query}%", per_page, offset)).fetchall()
        count_sql = f"SELECT COUNT(*) FROM users WHERE {filter_by} LIKE %s"
        total = conn.execute(count_sql, (f"%{query}%",)).fetchone()['count']
    else:
        users = conn.execute('SELECT * FROM users LIMIT %s OFFSET %s', (per_page, offset)).fetchall()
        total = conn.execute('SELECT COUNT(*) FROM users').fetchone()['count']
    conn.close()

    total_pages = (total + per_page - 1) // per_page
    return render_template('directory.html', users=users, page=page, total_pages=total_pages, filter_by=filter_by, query=query)

if __name__ == '__main__':
    app.run(debug=True)