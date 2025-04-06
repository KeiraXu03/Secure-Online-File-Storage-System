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
with app.app_context():
    db.create_all()
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
# 注册页面
@app.route('/register')
def registerhtml():
    return render_template('register.html')
# 注册页面
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
             # 生成 OTP 并保存密钥
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            session['provisioning_uri'] = provisioning_uri
            session['otp_secret'] = otp_secret
            return jsonify({'status': 'success',
                            'message': 'Registration successful!',
                            'provisioning_uri': provisioning_uri})
        except:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Username/email already exists!'}), 400

# 登录页面
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
    # 生成随机密钥
    otp_secret = pyotp.random_base32()
    
    # 构建标准URI
    provisioning_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(
        name=user,
        issuer_name="Your App Name"
    )
    
    # 生成二维码图像
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
        # 如果 session 信息缺失，提示用户重新登录或注册
        return jsonify({'status': 'error', 'message': 'Session expired, please log in again.'}), 400

    if request.method == 'POST':
        try:
            otp = request.form.get('otp')  # 获取用户输入的 OTP
            if not otp:
                error = 'OTP is required!'
                raise ValueError(error)

            # 验证用户输入的 OTP
            totp = pyotp.TOTP(otp_secret)
            if totp.verify(otp):  # 验证 OTP 是否正确
                # 更新数据库，启用 MFA
                user = User.query.filter_by(username=username).first()
                if user:
                    user.mfa_enabled = True  # 假设 User 模型有 mfa_enabled 字段
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
            db.session.rollback()  # 确保数据库操作回滚

    # 返回设置 OTP 的页面
    return jsonify({'status': 'error', 'message': error}), 400


@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        # 获取表单数据
        username = request.form.get('username')
        email = request.form.get('email')
        otp = request.form.get('otp')
        new_password = request.form.get('newPassword')
        confirm_password = request.form.get('confirmPassword')

        # 验证输入是否完整
        if not all([username, email, otp, new_password, confirm_password]):
            return jsonify({'status': 'error', 'message': 'All fields are required!'}), 400

        # 验证新密码和确认密码是否一致
        if new_password != confirm_password:
            return jsonify({'status': 'error', 'message': 'Passwords do not match!'}), 400

        # 查找用户
        user = User.query.filter_by(username=username, email=email).first()
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found!'}), 404

        # 验证 OTP
        totp = pyotp.TOTP(user.otp_secret)
        if not totp.verify(otp):
            return jsonify({'status': 'error', 'message': 'Invalid OTP!'}), 400

        # 更新密码
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Password reset successful!'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'status': 'error', 'message': f'Error resetting password: {str(e)}'}), 500
    
@app.route('/upload', methods=['POST'])
def upload_file():
    UPLOAD_FOLDER = './upload/'+session.get('username')+"/"
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    try:
        # Check if file is uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # Serialize keys
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Encrypt file data in chunks
        file_data = file.read()
        chunk_size = 190  # RSA-OAEP limitation
        encrypted_chunks = []
        
        for i in range(0, len(file_data), chunk_size):
            chunk = file_data[i:i + chunk_size]
            encrypted_chunk = public_key.encrypt(
                chunk,
                OAEP(
                    mgf=MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        
        # Combine encrypted chunksfilename = file.filename
        file_size = len(file.read())  # Get file size in bytes
        file.seek(0)  # Reset file pointer after reading size

        # Generate a unique file ID
        username = session.get('username')
        filename = file.filename
        fileid = generate_file_id(username, filename)

        encrypted_data = b''.join(encrypted_chunks)
        
        # Save encrypted file

        save_path = os.path.join(UPLOAD_FOLDER, hashlib.sha256(filename.encode()).hexdigest() + '.enc')
        with open(save_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
            new_file = files(
            fileid=fileid,
            filename=hashlib.sha256(filename.encode()).hexdigest(),
            owner=hashlib.sha256(username.encode()).hexdigest(),
            shared_to='',  # Initially no sharing
            file_path=save_path,
            file_size=file_size
        )
        db.session.add(new_file)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'File encrypted and stored securely',
            'public_key': public_key_pem,
            'private_key': private_key_pem
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
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
        username=session.get('username')
        user = User.query.filter_by(username=username).first()
        otp_secret = user.otp_secret

        totp = pyotp.TOTP(otp_secret)
        if not totp.verify(otp):
            return jsonify({'status': 'error', 'message': 'Invalid OTP!'})

        # Hash filename and username
        hashed_filename = hashlib.sha256(filename.encode()).hexdigest()
        hashed_owner = hashlib.sha256(username.encode()).hexdigest()
        filesid = generate_file_id(username, filename)
        # Query file information
        file_entry = files.query.filter_by(fileid=filesid).first()
        if not file_entry:
            return jsonify({'status': 'error', 'message': 'File not found!'})

        # Check ownership or sharing permissions
        if file_entry.owner == hashed_owner or username in file_entry.share_to.split(','):
            # Return file content
            filepath = file_entry.file_path
            try:
                # Read the encrypted file
                with open(filepath, 'rb') as enc_file:
                    encrypted_data = enc_file.read()

                # Decrypt the file using the user's private key
                private_key_pem = request.form.get('private_key')
                print(private_key_pem)
                print(encrypted_data)
                file_content = decrypt_file(encrypted_data, private_key_pem)

                # Return file content
                return jsonify({'status': 'success', 
                                'file': {
                                    'filename': filename,
                                    'owner': username,
                                    'file_size': len(file_content),
                                    'file_content': file_content
                                }}), 200
            except Exception as e:
                return jsonify({'status': 'error', 'message': f'Error reading or decrypting file: {str(e)}'})

    except Exception as e:
        # Handle exceptions and return error messages
        return jsonify({'status': 'error', 'message': f'Error processing request: {str(e)}'})

def decrypt_file(encrypted_data, private_key_pem):
    try:
        # 加载私钥
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),  # 私钥是以字符串形式存储的 PEM 格式
            password=None  # 如果私钥未加密，密码设置为 None
        )

        # 定义分块大小
        chunk_size = 256  # RSA 2048 位密钥的解密块大小（与加密块大小对应）
        decrypted_chunks = []

        # 分块解密
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

        # 合并所有解密后的块
        decrypted_data = b''.join(decrypted_chunks)

        return decrypted_data.decode('utf-8')  # 返回解密后的文件内容（假设是 UTF-8 编码）
    except Exception as e:
        raise ValueError(f"Error decrypting file: {str(e)}")

if __name__ == '__main__':
    # 确保在应用上下文中创建数据库
    with app.app_context():
        db.create_all()
    app.run(debug=True)
