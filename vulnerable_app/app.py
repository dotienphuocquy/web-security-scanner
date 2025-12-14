"""
Vulnerable Web Application for Testing
WARNING: This application intentionally contains security vulnerabilities
DO NOT deploy to production or public servers!
"""

from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'vulnerable-secret-key-do-not-use'

# Database setup
DB_PATH = 'vulnerable_app/vulnerable_app.db'


def init_db():
    """Initialize the database with sample data"""
    # Create database directory if not exists
    os.makedirs('vulnerable_app', exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')

    # Create posts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Create comments table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER,
            comment TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Insert sample users (if not exists)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        sample_users = [
            ('admin', 'admin123', 'admin@example.com', 'admin'),
            ('user1', 'password123', 'user1@example.com', 'user'),
            ('john', 'john123', 'john@example.com', 'user'),
            ('alice', 'alice456', 'alice@example.com', 'user')
        ]
        cursor.executemany(
            'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
            sample_users
        )

    # Insert sample posts (if not exists)
    cursor.execute("SELECT COUNT(*) FROM posts")
    if cursor.fetchone()[0] == 0:
        sample_posts = [
            ('Welcome to Vulnerable Blog', 'This is a demo blog with intentional security flaws for testing purposes.', 'admin'),
            ('SQL Injection Demo', 'Try to exploit the search and login functionality!', 'admin'),
            ('XSS Vulnerability Testing', 'Test XSS in comments and search features.', 'user1')
        ]
        cursor.executemany(
            'INSERT INTO posts (title, content, author) VALUES (?, ?, ?)',
            sample_posts
        )

    conn.commit()
    conn.close()


@app.route('/')
def index():
    """Home page"""
    return render_template('vulnerable_index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register page - VULNERABLE to SQL Injection"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # VULNERABLE: SQL Injection - Check if user exists
        query = f"SELECT * FROM users WHERE username='{username}'"
        print(f"[DEBUG] Query: {query}")

        try:
            cursor.execute(query)
            existing_user = cursor.fetchone()

            if existing_user:
                conn.close()
                return render_template('vulnerable_register.html', error='Username already exists')

            # Insert new user (safe query to avoid breaking registration)
            cursor.execute(
                'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                (username, password, email, 'user')
            )
            conn.commit()
            conn.close()

            return redirect(url_for('login'))

        except Exception as e:
            conn.close()
            # VULNERABLE: Exposing SQL errors
            return render_template('vulnerable_register.html', error=f'Database Error: {str(e)}')

    return render_template('vulnerable_register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page - VULNERABLE to SQL Injection"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        # VULNERABLE: SQL Injection - Direct string concatenation
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"[DEBUG] Query: {query}")  # For testing purposes

        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()

            if user:
                session['user'] = username
                session['role'] = user[4] if len(user) > 4 else 'user'
                return redirect(url_for('dashboard'))
            else:
                return render_template('vulnerable_login.html', error='Invalid credentials')
        except Exception as e:
            conn.close()
            # VULNERABLE: Error-based SQL Injection - Exposing SQL errors
            return render_template('vulnerable_login.html', error=f'Database Error: {str(e)}')

    return render_template('vulnerable_login.html')


@app.route('/search')
def search():
    """Search page - VULNERABLE to SQL Injection and XSS"""
    query = request.args.get('q', '')
    results = []

    if query:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # VULNERABLE: SQL Injection
        sql_query = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
        print(f"[DEBUG] Query: {sql_query}")

        try:
            cursor.execute(sql_query)
            results = cursor.fetchall()
        except Exception as e:
            # VULNERABLE: Exposing SQL errors
            results = [('error', f'SQL Error: {str(e)}', '', '')]

        conn.close()

    # VULNERABLE: XSS - Rendering user input without escaping
    return render_template('vulnerable_search.html', query=query, results=results)


@app.route('/post/<int:post_id>')
def view_post(post_id):
    """View post - VULNERABLE to XSS in comments"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get post
    cursor.execute("SELECT * FROM posts WHERE id=?", (post_id,))
    post = cursor.fetchone()

    if not post:
        conn.close()
        return render_template('vulnerable_post.html', post=None, comments=[], error="Post not found")

    # Get comments
    cursor.execute("SELECT * FROM comments WHERE post_id=?", (post_id,))
    comments = cursor.fetchall()

    conn.close()

    return render_template('vulnerable_post.html', post=post, comments=comments)


@app.route('/post/<int:post_id>/comment', methods=['POST'])
def add_comment(post_id):
    """Add comment - VULNERABLE to Stored XSS"""
    comment = request.form.get('comment', '')
    author = session.get('user', 'Anonymous')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # VULNERABLE: Storing unsanitized user input
    cursor.execute(
        'INSERT INTO comments (post_id, comment, author) VALUES (?, ?, ?)',
        (post_id, comment, author)
    )

    conn.commit()
    conn.close()

    return redirect(url_for('view_post', post_id=post_id))


@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    if 'user' not in session:
        return redirect(url_for('login'))

    return render_template('vulnerable_dashboard.html', username=session.get('user'))


@app.route('/profile')
def profile():
    """User profile - Shows logged-in user's profile, or allows SQL injection via id param"""
    # If user is logged in, show their profile by default
    if 'user' in session:
        username = session.get('user')

        # Allow SQL injection testing via 'id' parameter (for scanner testing)
        user_id = request.args.get('id')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        if user_id:
            # VULNERABLE: SQL Injection when using id parameter
            query = f"SELECT * FROM users WHERE id={user_id}"
            print(f"[DEBUG] Query: {query}")

            try:
                cursor.execute(query)
                user = cursor.fetchone()
                error_msg = None
            except Exception as e:
                user = None
                error_msg = f"Database Error: {str(e)}"  # VULNERABLE: Exposing SQL errors
                print(f"Error: {e}")
        else:
            # Show current user's profile (safe query)
            cursor.execute("SELECT * FROM users WHERE username=?", (username,))
            user = cursor.fetchone()
            error_msg = None

        conn.close()
        return render_template('vulnerable_profile.html', user=user, error=error_msg)
    else:
        # Not logged in - redirect to login
        return redirect(url_for('login'))


@app.route('/admin/users')
def admin_users():
    """Admin panel - View all users - VULNERABLE to SQL Injection"""
    # Fixed: Check if user is logged in AND has admin role
    if 'user' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        return render_template('vulnerable_error.html', error='Access Denied: Admin role required'), 403

    search = request.args.get('search', '')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if search:
        # VULNERABLE: SQL Injection in search
        query = f"SELECT * FROM users WHERE username LIKE '%{search}%' OR email LIKE '%{search}%'"
        print(f"[DEBUG] Query: {query}")
        try:
            cursor.execute(query)
            users = cursor.fetchall()
            error = None
        except Exception as e:
            users = []
            error = f"Database Error: {str(e)}"  # VULNERABLE: Exposing SQL errors
    else:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        error = None

    conn.close()
    return render_template('vulnerable_admin_users.html', users=users, search=search, error=error)


@app.route('/admin/create_post', methods=['GET', 'POST'])
def admin_create_post():
    """Admin - Create post - VULNERABLE to Stored XSS"""
    # Fixed: Check admin role
    if 'user' not in session:
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        return render_template('vulnerable_error.html', error='Access Denied: Admin role required'), 403

    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        author = session.get('user')

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # VULNERABLE: Storing unsanitized user input (XSS)
        cursor.execute(
            'INSERT INTO posts (title, content, author) VALUES (?, ?, ?)',
            (title, content, author)
        )

        conn.commit()
        post_id = cursor.lastrowid
        conn.close()

        return redirect(url_for('view_post', post_id=post_id))

    return render_template('vulnerable_admin_create_post.html')


@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/posts')
def list_posts():
    """List all posts - VULNERABLE to SQL Injection"""
    # Get filter parameter
    author = request.args.get('author', '')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if author:
        # VULNERABLE: SQL Injection in WHERE clause
        query = f"SELECT * FROM posts WHERE author='{author}'"
        print(f"[DEBUG] Query: {query}")
        try:
            cursor.execute(query)
            posts = cursor.fetchall()
            error = None
        except Exception as e:
            # VULNERABLE: Exposing SQL errors
            posts = []
            error = f"SQL Error: {str(e)}"
    else:
        cursor.execute("SELECT * FROM posts ORDER BY created_at DESC")
        posts = cursor.fetchall()
        error = None

    # Get comment count for each post
    posts_with_comments = []
    for post in posts:
        cursor.execute("SELECT COUNT(*) FROM comments WHERE post_id=?", (post[0],))
        comment_count = cursor.fetchone()[0]
        posts_with_comments.append((*post, comment_count))

    conn.close()
    return render_template('vulnerable_posts_list.html', posts=posts_with_comments, error=error, author=author)


def start_vulnerable_app():
    """Start the vulnerable application"""
    init_db()
    print("\n" + "="*60)
    print("VULNERABLE WEB APPLICATION - FOR TESTING ONLY")
    print("="*60)
    print("Starting on http://127.0.0.1:8080")
    print("\nTest Credentials:")
    print("  Username: admin  | Password: admin123")
    print("  Username: user1  | Password: password123")
    print("\nVulnerabilities included:")
    print("  - SQL Injection: Login, Register, Search, Profile, Posts, Admin Users (6 endpoints)")
    print("  - Reflected XSS: Search (1 endpoint)")
    print("  - Stored XSS: Comments, Admin Posts (2 endpoints)")
    print("\nTotal: 9 SQL Injection and XSS vulnerabilities")
    print("\nWARNING: DO NOT DEPLOY TO PRODUCTION!")
    print("="*60 + "\n")

    app.run(debug=True, host='0.0.0.0', port=8080)


if __name__ == '__main__':
    start_vulnerable_app()
