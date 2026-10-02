import os
from flask import Flask, request, render_template_string, redirect, url_for, session, send_file
from cryptography.fernet import Fernet
import io

app = Flask(__name__)
app.secret_key = 'super_secure_secret_key_for_internship'

# Create a folder to store encrypted files safely
UPLOAD_FOLDER = 'secure_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Generate an encryption key to lock files
KEY = Fernet.generate_key()
fernet = Fernet(KEY)

# Mock Database for user credentials and roles
USERS = {
    "admin@example.com": {"password": "admin123", "role": "Admin"},
    "user@example.com": {"password": "user123", "role": "User"}
}

# In-memory database to keep track of uploaded files and owners
FILES_DB = {}

# HTML layout for Login, Upload, and Download UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Sharing Application</title>
</head>
<body style="font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9;">
    <h2>🔐 CodSoft Cyber Security - Task 5 (Secure File Sharing)</h2>
    
    {% if not session.get('user') %}
        <h3>👤 User Login</h3>
        <form method="POST" action="/login">
            <input type="email" name="email" placeholder="Email (admin@example.com or user@example.com)" required style="width:350px; padding:8px;"><br><br>
            <input type="password" name="password" placeholder="Password (admin123 or user123)" required style="width:350px; padding:8px;"><br><br>
            <button type="submit" style="padding: 8px 15px; background: #007BFF; color:white; border:none; cursor:pointer;">Login</button>
        </form>
        {% if error %}<p style="color:red;">{{ error }}</p>{% endif %}
    {% else %}
        <p>Logged in as: <b>{{ session['user'] }}</b> | Role: <b style="color:green;">{{ session['role'] }}</b> | <a href="/logout">Logout</a></p>
        
        <!-- File Upload Form -->
        <h3>📤 Secure File Upload</h3>
        <form method="POST" action="/upload" enctype="multipart/form-data">
            <input type="file" name="file" required><br><br>
            <button type="submit" style="padding: 8px 15px; background: #28a745; color:white; border:none; cursor:pointer;">Encrypt & Upload</button>
        </form>

        <!-- Available Files Table with Role-Based Access Control -->
        <h3>📁 Available Secure Files</h3>
        <table border="1" cellpadding="8" style="border-collapse: collapse; width: 600px; background: white;">
            <tr style="background: #eee;">
                <th>File Name</th>
                <th>Uploaded By (Owner)</th>
                <th>Action</th>
            </tr>
            {% for filename, info in files.items() %}
                <!-- RBAC Rule: Admin can view all files, User can only see their own files -->
                {% if session['role'] == 'Admin' or info['owner'] == session['user'] %}
                <tr>
                    <td>{{ filename }}</td>
                    <td>{{ info['owner'] }}</td>
                    <td><a href="/download/{{ filename }}" style="color: #007BFF;">Decrypt & Download</a></td>
                </tr>
                {% endif %}
            {% endfor %}
        </table>
    {% endif %}
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, files=FILES_DB)

# User Authentication Logic
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    if email in USERS and USERS[email]['password'] == password:
        session['user'] = email
        session['role'] = USERS[email]['role']
        return redirect(url_for('home'))
    return render_template_string(HTML_TEMPLATE, error="Invalid Email or Password!", files=FILES_DB)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# File Encryption and Upload Logic
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('home'))
    
    file = request.files.get('file')
    if file and file.filename != '':
        filename = file.filename
        file_data = file.read()
        
        # Encrypt the file using AES / Fernet before storing
        encrypted_data = fernet.encrypt(file_data)
        
        # Save the encrypted data safely into the folder
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        with open(filepath, 'wb') as f:
            f.write(encrypted_data)
            
        # Store metadata in database
        FILES_DB[filename] = {'owner': session['user']}
        
    return redirect(url_for('home'))

# File Decryption and Download with RBAC Check
@app.route('/download/<filename>')
def download(filename):
    if 'user' not in session:
        return redirect(url_for('home'))
        
    file_info = FILES_DB.get(filename)
    if not file_info:
        return "File Not Found!", 404
        
    # Role-Based Access Control (RBAC) security check
    if session['role'] != 'Admin' and file_info['owner'] != session['user']:
        return "⚠️ Access Denied: You do not have permission to download this file!", 403

    # Read and decrypt the file on the fly for the valid user
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    with open(filepath, 'rb') as f:
        encrypted_data = f.read()
        
    decrypted_data = fernet.decrypt(encrypted_data)
    
    return send_file(
        io.BytesIO(decrypted_data),
        download_name=filename,
        as_attachment=True
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)

