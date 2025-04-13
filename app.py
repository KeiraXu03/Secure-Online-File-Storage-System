import hashlib
import os
from sqlite3 import IntegrityError
import sqlite3
from flask import Flask, session,request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from flask_session import Session
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
import base64
import pyotp
import qrcode
from datetime import datetime, timezone
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///storage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['UPLOAD_FOLDER'] = './uploads'  # Directory to save uploaded files
app.config['SECRET_KEY'] = 'xuzhuoning'
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True 
app.config['SESSION_COOKIE_SAMESITE'] = 'strict'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
Session(app)
# 数据库模型
class User(db.Model):
    username = db.Column(db.String(80), unique=True, primary_key=True)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False)
    otp_secret=db.Column(db.String(120), unique=True, nullable=False)
    mfa_enabled = db.Column(db.Boolean, default=False)  # 是否启用 MFA
    def __repr__(self):
        return f'<User {self.username}>'
class files(db.Model):
    fileid = db.Column(db.String(80), unique=True, primary_key=True)  # Unique file ID (hashed)
    filename = db.Column(db.String(200), nullable=False)  # Original file name
    owner = db.Column(db.String(120), nullable=False)  # Username of the file owner
    shared_to = db.Column(db.String(20), nullable=True)  # Comma-separated list of usernames
    file_path = db.Column(db.String(200), nullable=False)  # File storage path
    file_size = db.Column(db.Integer, nullable=False)  # File size in bytes
    def __repr__(self):
        return f'<files {self.fileid}>'
class Logs(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), nullable=False)   # user
    action = db.Column(db.String(200), nullable=False)     # discription like "LOGIN", "REGISTER", "UPLOAD", "DELETE"
    detail = db.Column(db.String(500), nullable=True)      # details
    timestamp = db.Column(db.DateTime, nullable=False)     # time
    def __repr__(self):
        return f'<Logs id={self.id} username={self.username} action={self.action}>'

with app.app_context():
    db.create_all()

def create_log(username, action, detail=""): #write log
    new_log = Logs(
        username=username,
        action=action,
        detail=detail,
        timestamp=datetime.now(timezone.utc)  # use timezone-aware datetime
    )
    db.session.add(new_log)
    db.session.commit()

# 首页
@app.route('/')
def hello():
    return render_template('login.html')


@app.route('/index')
def index():
    return render_template('index.html',username=session.get('username'))

@app.route('/login')
def login_page():
    return render_template('login.html')
# register page
@app.route('/register')
def registerhtml():
    return render_template('register.html')
# register API
@app.route('/register_spqce', methods=['POST'])  # Check if URL should be '/register_space'
def register():
    if request.method == 'POST':
        # Add repassword retrieval
        username = request.form.get('userid')
        password = request.form.get('password')
        repassword = request.form.get('repassword')  # Added missing field
        email = request.form.get('email')
        role = request.form.get('role')

        # Validate all required fields
        if not all([username, password, repassword, email, role]):
            return jsonify({'status': 'error', 'message': 'All fields are required!'}), 400
            
        if password != repassword:
            return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400
            
        if role not in ['user', 'admin']:
            return jsonify({'status': 'error', 'message': 'Invalid role selected!'}), 400
        
        otp_secret, provisioning_uri= generate_otp(username)

        # Remove non-existent gender field
        new_user = User(
            username=username,
            password=bcrypt.generate_password_hash(password).decode('utf-8'),
            email=email,
            role=role,  # Removed undefined gender parameter
            otp_secret=otp_secret
        )      
        # Add error handling for DB operations
        try:
             # generate_otp(username)
            db.session.add(new_user)
            db.session.commit()
            create_log(username=username, action="REGISTER", detail="User registered successfully") # register log
            session['username'] = username
            session['provisioning_uri'] = provisioning_uri
            session['otp_secret'] = otp_secret
            return jsonify({'status': 'success',
                            'message': 'Registration successful!',
                            'provisioning_uri': provisioning_uri})
        except:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Username/email already exists!'}), 400

# login API
@app.route('/login_check', methods=['POST'])
def login():
    if request.method == 'POST':
        # Match frontend field names
        username = request.form.get('username')  # Changed from 'userid'
        password = request.form.get('password')

        if not username or not password:
            return jsonify({
                "status": "error",
                "message": "Both fields are required"
            }), 400

        try:
            user = User.query.filter_by(username=username).first()
            
            # Enhanced password verification
            if user and bcrypt.check_password_hash(user.password, password):
                session['username'] = user.username
                create_log(username=user.username, action="LOGIN", detail="User logged in") # write login log
                # Return complete user data
                access_token = create_access_token(identity={
                    "username": user.username,
                    "role": user.role,
                    "email": user.email
                })
                return jsonify({
                    "status": "success",
                    "message": "Login successful",
                    "user": {
                        "username": user.username,
                        "role": user.role,
                        "email": user.email
                    },
                    "access_token": access_token
                }), 200
            
            return jsonify({
                "status": "error",
                "message": "Invalid credentials"
            }), 401

        except Exception as e:
            return jsonify({
                "status": "error",
                "message": "Server error"
            }), 500
def generate_otp(user):
    # generate a random base32 secret key
    otp_secret = pyotp.random_base32()
    
    # generate a provisioning URI for the OTP
    provisioning_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user,
        issuer_name="Your App Name"
    )
    
    # generate a QR code for the provisioning URI
    qr = qrcode.make(provisioning_uri)
    
    return otp_secret, provisioning_uri

@app.route('/findpassword_page')
def findpassword_page():
    return render_template(
        'find_password.html'
    )
@app.route('/otp', methods=['GET'])
def otp_page():
    return render_template(
        'otp_setting.html',
        username = session.get('username'),
        provisioning_uri = session.get('provisioning_uri')
    )
@app.route('/otp_setting', methods=['GET', 'POST'])
def otp_setting():
    error = None
    username = session.get('username')
    provisioning_uri = session.get('provisioning_uri')
    otp_secret = session.get('otp_secret')

    if not username or not provisioning_uri or not otp_secret:
        # if session expired, redirect to login page
        return jsonify({'status': 'error', 'message': 'Session expired, please log in again.'}), 400

    if request.method == 'POST':
        try:
            otp = request.form.get('otp')  # get OTP from user
            if not otp:
                error = 'OTP is required!'
                raise ValueError(error)

            # veirfy OTP
            totp = pyotp.TOTP(otp_secret)
            if totp.verify(otp):  # verify OTP
                # update user record in database
                user = User.query.filter_by(username=username).first()
                if user:
                    user.mfa_enabled = True  # 
                    db.session.commit()
                    return jsonify({'status': 'success', 'message': 'OTP setup successful!'})
                else:
                    error = 'User not found!'
                    raise ValueError(error)
            else:
                error = 'Invalid OTP!'
        except Exception as e:
            error = f'Error adding OTP: {str(e)}'
        finally:
            db.session.rollback()  # ensure session is rolled back on error
    # If OTP setup fails, return error message
    # and redirect to OTP setup page

    return jsonify({'status': 'error', 'message': error}), 400


@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        # getting data from request
        username = request.form.get('username')
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        # ensure all fields are provided
        if not all([username, email, otp, new_password, confirm_password]):
            return jsonify({'status': 'error', 'message': 'All fields are required!'}), 400

        # validate new password
        if new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400

        # find user by username and email
        user = User.query.filter_by(username=username, email=email).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found!'}), 404

        # verify OTP
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp):
            return jsonify({'status': 'error', 'message': 'Invalid OTP!'}), 400

        # update password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        create_log(username=session.get('username'), action="PassowrdReset", detail=f"Password has been reset.")
        return jsonify({'status': 'success', 'message': 'Password reset successful!'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error resetting password: {str(e)}'}), 500
    
@app.route('/upload', methods=['POST'])
def upload_file():
    UPLOAD_FOLDER = './upload/' + session.get('username') + "/"
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # 获取上传文件
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    # getting public key
    public_key_pem = request.form.get('public_key')
    # save file
    file_data = file.read()
    file_size = len(file_data)
    username = session.get('username')
    filename = file.filename  # 原始文件名
    fileid = generate_file_id(username, filename)
    save_path = os.path.join(UPLOAD_FOLDER, hashlib.sha256(filename.encode()).hexdigest() + '.enc')
    with open(save_path, 'wb') as f:
        f.write(file_data)
    # return file information
    # 计算文件的 SHA-256 哈希值
    new_file = files(fileid=fileid,
                     filename=hashlib.sha256(filename.encode()).hexdigest(),
                     owner=hashlib.sha256(username.encode()).hexdigest(),
                     shared_to='',
                     file_path=save_path,
                     file_size=file_size)
    db.session.add(new_file)
    db.session.commit()
    create_log(username=username, action="UPLOAD", detail=f"Uploaded file: {filename}")
    # return file information
    return jsonify({'status': 'success', 'message': 'File uploaded (encrypted by client)'}), 200

    
# Helper function to generate a unique file ID
def generate_file_id(username, filename):
    # Combine username and filename and create a SHA-256 hash
    unique_string = f"{username}_{filename}"
    return hashlib.sha256(unique_string.encode()).hexdigest()

@app.route('/query_file', methods=['POST'])
def handle_file_query():
    try:
        filename = request.form.get('filename')
        otp = request.form.get('otp')
        username = session.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found in session'}), 404
        otp_secret = user.otp_secret
        totp = pyotp.TOTP(otp_secret)
        if not totp.verify(otp):
            return jsonify({'status': 'error', 'message': 'Invalid OTP!'})
        hashed_filename = hashlib.sha256(filename.encode()).hexdigest()# Hash filename

#       hashed_owner = hashlib.sha256(username.encode()).hexdigest()
#       filesid = generate_file_id(username, filename)
#       # Query file information
#       file_entry = files.query.filter_by(fileid=filesid).first()
#       if not file_entry:
#           return jsonify({'status': 'error', 'message': 'File not found!'})

#       # Check ownership or sharing permissions
#       if file_entry.owner == hashed_owner or username in file_entry.share_to.split(','):
#           # Return file content
#           filepath = file_entry.file_path

        #change starts
        candidate_files = files.query.filter_by(filename=hashed_filename).all()
        if not candidate_files:
            return jsonify({'status': 'error', 'message': 'File not found!'}), 404
        #candidate_files，see if the file is shared
        hashed_current_user = hashlib.sha256(username.encode()).hexdigest()
        allowed_file_entry = None
        for f in candidate_files:
            share_list = f.shared_to.split(',') if f.shared_to else []
            if (f.owner == hashed_current_user) or (username in share_list):
                # find the file entry that matches the current user
                allowed_file_entry = f
                break
        if not allowed_file_entry:
            return jsonify({'status': 'error', 'message': 'No permission to access this file'}), 403
        filepath = allowed_file_entry.file_path
        try:
            with open(filepath, 'rb') as enc_file:
                encrypted_data = enc_file.read()
            # Encode the encrypted binary content into a string using Base64 and send it to the front end
            encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
            # Determine whether the current user is the owner, used for front-end interface control
            is_owner = (allowed_file_entry.owner == hashlib.sha256(username.encode()).hexdigest())
            create_log(username=username, action="Query", detail=f"Query file: {filename}")
            return jsonify({
                'status': 'success',
                'file': {
                    'filename': filename,
                    'owner': username,  # Currently viewing user
                    'file_size': allowed_file_entry.file_size,
                    'encrypted_content': encrypted_base64
                },
                'is_owner': is_owner
            }), 200
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Error reading file: {e}'}), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error processing request: {str(e)}'
        })

# Not used here
# decrypt file is conducted in the client
def decrypt_file(encrypted_data, private_key_pem):
    try:
        # Loading Private Key
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),  # The private key is stored as a string in PEM format.
            password=None 
        )

        chunk_size = 256 
        decrypted_chunks = []

        for i in range(0, len(encrypted_data), chunk_size):
            chunk = encrypted_data[i:i + chunk_size]
            decrypted_chunk = private_key.decrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            decrypted_chunks.append(decrypted_chunk)
        decrypted_data = b''.join(decrypted_chunks)

        return decrypted_data.decode('utf-8') 
    except Exception as e:
        raise ValueError(f"Error decrypting file: {str(e)}")

# delete file API
@app.route('/delete_file/<fileid>', methods=['POST'])
def delete_file(fileid):
    fileid=generate_file_id(session.get('username'), fileid)
    # find file record
    file = files.query.filter_by(fileid=fileid).first()
    if not file:
        return jsonify({'error': 'Permission denied'}), 404
    # veirfy owner
    if file.owner != hashlib.sha256(session.get('username').encode()).hexdigest():
        return jsonify({'error': 'Permission denied'}), 403
    try:
        #delete from database
        os.remove(file.file_path) 
        db.session.delete(file)
        db.session.commit()
        create_log(username=session.get('username'), action="DELETE", detail=f"Deleted file: {file.filename}") # delete log
        return jsonify({'message': 'File deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': 'Failed to delete file', 'details': str(e)}), 500

@app.route('/share_file', methods=['POST'])
def share_file():
    current_username = session.get('username')
    if not current_username:
        return jsonify({'status': 'error', 'message': 'Not logged in'}), 401
    
    filename = request.form.get('filename')
    target_user = request.form.get('target_user')
    if not filename or not target_user:
        return jsonify({'status': 'error', 'message': 'filename and target_user required'}), 400
    fileid = generate_file_id(current_username, filename)
    file_entry = files.query.filter_by(fileid=fileid).first()
    if not file_entry:
        return jsonify({'status': 'error', 'message': 'File not found or no permission'}), 404
    #veirfy owner
    hashed_owner = hashlib.sha256(current_username.encode()).hexdigest()
    if file_entry.owner != hashed_owner:
        return jsonify({'status': 'error', 'message': 'Only owner can share'}), 403
    try:
        existing = file_entry.shared_to  # use , to split
        if existing:
            shared_list = existing.split(',')
        else:
            shared_list = []

        if target_user not in shared_list:
            shared_list.append(target_user)
            file_entry.shared_to = ",".join(shared_list)
            db.session.commit()

            # write share log
            create_log(
                username=current_username, 
                action="SHARE",
                detail=f"Shared file {filename} to {target_user}"
            )
            return jsonify({'status': 'success', 'message': f"File '{filename}' shared to {target_user}"}), 200
        else:
            return jsonify({'status': 'success', 'message': f"{target_user} already in shared list"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error sharing file: {str(e)}'}), 500


# admin api
@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    current_username = session.get('username')
    if not current_username:
        return "Please login first", 401

    user = User.query.filter_by(username=current_username).first()
    if not user:
        return "User not found", 404

    if user.role != 'admin':
        return "Forbidden: Admin only", 403

    all_logs = Logs.query.order_by(Logs.timestamp.desc()).all()
    return render_template('admin_dashboard.html', logs=all_logs)


@app.route('/update_file', methods=['POST'])
def update_file():
    try:
        filename = request.form.get('filename')
        new_content_b64 = request.form.get('newContent')  # get the new content in Base64
        reuse_flag = request.form.get('reuse_key')
        # verify
        if not filename or new_content_b64 is None or reuse_flag is None:
            return jsonify({'status': 'error', 'message': 'Missing required data'}), 400
        # find file
        hashed_filename = hashlib.sha256(filename.encode()).hexdigest()
        candidate_files = files.query.filter_by(filename=hashed_filename).all()
        if not candidate_files:
            return jsonify({'status': 'error', 'message': 'File not found!'}), 404
        hashed_current_user = hashlib.sha256(session.get('username').encode()).hexdigest()
        allowed_file_entry = None
        for f in candidate_files:
            #Only the file owner can edit it, shared users can skip it
            if f.owner == hashed_current_user:
                allowed_file_entry = f
                break
        if not allowed_file_entry:
            return jsonify({'status': 'error', 'message': 'No permission to edit this file'}), 403
        # Decode Base64 encrypted content into binary data
        try:
            new_encrypted_data = base64.b64decode(new_content_b64)
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Invalid encrypted data'}), 400
        #Overwrite a file
        save_path = allowed_file_entry.file_path
        with open(save_path, 'wb') as f:
            f.write(new_encrypted_data)
        # Record edit log
        if reuse_flag.lower() == 'true':
            create_log(username=session.get('username'), action="EDIT", detail=f"Edited file (reuse old key): {filename}")
        else:
            create_log(username=session.get('username'), action="EDIT", detail=f"Edited file (generated new key): {filename}")
        return jsonify({'status': 'success', 'message': f"File '{filename}' updated successfully"}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error updating file: {e}'}), 500



if __name__ == '__main__':
    # Make sure to create the database in the application context
    with app.app_context():
        db.create_all()
    app.run(debug=True)
