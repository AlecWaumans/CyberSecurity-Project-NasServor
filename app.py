import argparse
import base64
import getpass
import os

import pyotp
import qrcode
import re
import requests
import stat
import time
import uuid

from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
from flask import Flask, send_file, render_template, request, flash, redirect, url_for, session, abort, make_response, current_app, jsonify
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman
from flask_wtf import CSRFProtect, FlaskForm
from functools import wraps
from io import BytesIO
from sqlalchemy import or_, and_
from werkzeug.utils import secure_filename, safe_join
from wtforms import StringField, FileField, SelectField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError

################### CONFIG ###########################################################################################
# Configure the Flask app with necessary parameters like the database URI and secret key
load_dotenv() # Load values from .env into environment
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') # SQLite database URI from environment values
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')  # Secret key for session management (important for security) from environment values
app.config['UPLOAD_FOLDER'] = 'uploads'  # Directory where uploaded files will be stored
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', '0') == '1' # Flas debug mode through environment values
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}  # Define allowed file extensions for upload
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload to 16MB
app.config['_CHUNK'] = 1024 * 1024  # 1 MiB

# Path traversal hardening
DIR_TOKEN_RE = re.compile(r'^[0-9a-f]{32}$')
FILE_TOKEN_RE = re.compile(r'^[0-9a-f]{32}\.enc$')

# Rate-limit attempts per IP
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Secure session cookies
app.config['SESSION_COOKIE_SECURE'] = True # Transmits cookies via HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True # Prevent JavaScript from accessing cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Session timeout (auto logout after inactivity and timeout)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
ABSOLUTE_SESSION_TIMEOUT = timedelta(minutes=20)
INACTIVE_SESSION_TIMEOUT = timedelta(minutes=5)

# Initialize extensions like SQLAlchemy for database interaction, Bcrypt for password hashing, and Flask-Login for session management
db = SQLAlchemy(app)  # Database instance
bcrypt = Bcrypt(app)  # Bcrypt instance for password hashing
login_manager = LoginManager()  # Login manager to handle user sessions
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if the user is not authenticated

# Enable global CSRF protection
csrf = CSRFProtect(app)

# Enforce HTTPS with Talisman
csp = {
    'default-src': "'self'",  # Restricts all resources to the same origin by default
    'img-src': "'self' data: https://www.gstatic.com",  # Allow images from the same origin or inline images
    'style-src': "'self' https://www.gstatic.com",  # Allow styles only from the same origin and no inline styles
    'script-src': "'self' https://www.gstatic.com https://www.google.com https://cdn.jsdelivr.net 'wasm-unsafe-eval'", # Block inline <script> injection
    'object-src': "'none'", # Block Flash/Java and other plugin-based content
    'font-src': "'self'", # Allows only local fonts
    'form-action': "'self'", # Allows submitting forms only to our domain
    'base-uri': "'self'", # Block malicious use of <base> tag
    'frame-ancestors': "'self'", # Block app from being embedded in external iframes
    'frame-src': "https://www.google.com"
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    force_https_permanent=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,  # 1 year
    strict_transport_security_preload=True,
    strict_transport_security_include_subdomains=True,
)  # Apply Talisman to enforce HTTPS and set CSP

################## MODELS ############################################################################################
# User model representing the users in the database
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)  # Unique user ID
    username = db.Column(db.String(20), nullable=False, unique=True)  # Username field (unique for each user)
    password = db.Column(db.String(80), nullable=False)  # Password field
    role = db.Column(db.String(10), nullable=False, default='user')

    # Authentificator secret
    totp_secret = db.Column(db.String(16))  # TOTP secret for 2FA

# Model for storing user contacts (connections between users)
class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique contact ID
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Reference to the user who made the contact
    contact_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Reference to the user who is contacted

    user = db.relationship('User', foreign_keys=[user_id], backref='user_contacts')  # Relationship with the user who made the contact
    contact = db.relationship('User', foreign_keys=[contact_id], backref='contacted_users')  # Relationship with the contacted user

    __tablename__ = 'contacts'  # Set the table name for this model

    __table_args__ = (
        db.UniqueConstraint('user_id', 'contact_id', name='unique_contact'),
    )

# Model for managing contact requests (pending, accepted, or rejected)
class ContactRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Unique request ID
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Sender's user ID
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Receiver's user ID
    status = db.Column(db.String(20), nullable=False, default='pending')  # Status of the request ('pending', 'accepted', or 'rejected')

    # Relationships to access user data (sender and receiver)
    sender = db.relationship('User', foreign_keys=[sender_id], backref='outgoing_requests')  # Relationship with the sender user
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='incoming_requests')  # Relationship with the receiver user

    __tablename__ = 'contact_requests'  # Set the table name for this model

    __table_args__ = (
        db.UniqueConstraint('sender_id', 'receiver_id', name='unique_contact_request'),
    )

# Model for shared folders (folders shared between users)
class SharedFolder(db.Model):
    __tablename__ = 'shared_folder'  # Set the table name for this model

    id = db.Column(db.Integer, primary_key=True)  # Unique shared folder ID

    directory_id = db.Column(db.Integer, db.ForeignKey('directory_metadata.id'), nullable=False)
    directory = db.relationship('DirectoryMetadata', backref='shared_entries')

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Owner's user ID
    owner = db.relationship('User', foreign_keys=[owner_id], backref='owned_folders') # Relationship with the owner user

    shared_with_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # ID of the user the folder is shared with (nullable if no one is currently shared with)
    shared_with_user = db.relationship('User', foreign_keys=[shared_with_user_id], backref='shared_folders') # Relationship with the user the folder is shared with

    permissions = db.Column(db.String(128), nullable=False)  # Permissions for the shared folder (e.g., delete, add, download)

    def __repr__(self):
        return f"<SharedFolder directory_id={self.directory_id} owner_id={self.owner_id} shared_with={self.shared_with_user_id}>"

class Log(db.Model):
    __tablename__ = 'logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # nullable for unauthenticated actions
    action = db.Column(db.String(128), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    ip_address = db.Column(db.String(64))
    details = db.Column(db.Text)  # e.g. file name, result, etc.
    severity = db.Column(db.String(32))

    user = db.relationship('User', backref='logs')
    def __repr__(self):
        return f"<Log {self.action} by User ID {self.user_id} at {self.timestamp}>"

class FileMetadata(db.Model):
    __tablename__ = 'file_metadata'

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    directory_id = db.Column(db.Integer, db.ForeignKey('directory_metadata.id'))
    directory = db.relationship('DirectoryMetadata', backref='files')

    filename_enc = db.Column(db.String(256), nullable=False, unique=True) # UUID-based encrypted filename
    original_filename = db.Column(db.String(128), nullable=False)

    upload_date = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))

    user = db.relationship('User', backref='files_metadata')

    iv = db.Column(db.LargeBinary(12), nullable=False)
    salt = db.Column(db.LargeBinary(16), nullable=False)
    argon_time = db.Column(db.Integer, nullable=False, default=3)
    argon_mem = db.Column(db.Integer, nullable=False, default=65536)  # 64 MB
    argon_parallelism = db.Column(db.Integer, nullable=False, default=1)
    cipher = db.Column(db.String(32), nullable=False, default='AES-GCM-256-Argon2id')

class DirectoryMetadata(db.Model):
    __tablename__ = 'directory_metadata'

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    original_dir_name = db.Column(db.String(126), nullable=False)
    dir_name_enc = db.Column(db.String(256), unique=True)

    __table_args__ = (
        db.UniqueConstraint('owner_id', 'original_dir_name', name='unique_directory_name_per_user'),
    )
######################### FORMS #######################################################################################
# Form for user registration, with input validation
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})  # Username field
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=40)], render_kw={"placeholder": "Password"})  # Password field

    submit = SubmitField('Register')  # Submit button

    # Custom validation to check if the username already exists
    def validate_username(self, username):
        reserved = ['admin', 'administator', 'root', 'superuser']
        uname = username.data.strip().lower()

        if any(uname == r or uname.startswith(r) for r in reserved):
            log_action("auth.register_failed",
                       details=f"attempt to use reserved username '{username.data}'",
                       severity="WARNING")
            raise ValidationError("This username is reserved and cannot be used.")

        existing_user_username = User.query.filter_by(username=username.data).first()  # Check if username exists in the database
        if existing_user_username:
            log_action("auth.register_failed",
                       details=f"username='{username.data}' already exists",
                       severity="WARNING")
            raise ValidationError('That username already exists. Please choose a different one.')  # Raise error if username is already taken

    # Custom validation to check password strength
    def validate_password(form, field):
        valid, msg = validate_password_strength(field.data)
        if not valid:
            raise ValidationError(msg)

# Form for user login, also with validation
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})  # Username field
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})  # Password field

    submit = SubmitField('Login')  # Submit button

# Form for uploading files, including directory selection
class UploadForm(FlaskForm):
    file = FileField('File', validators=[InputRequired()])  # File upload field (required)
    directory = SelectField('Directory', coerce=str, choices=[])  # Dropdown to select a directory
    submit = SubmitField('Upload')  # Submit button

# Form for creating a new directory
class CreateDirectoryForm(FlaskForm):
    directory_name = StringField(
        'Directory Name',
        validators=[InputRequired(), Length(min=1, max=100)],  # Require inputs with a length limit
        render_kw={"placeholder": "Directory Name"}  # Placeholder text for the input field
    )
    submit = SubmitField('Create Directory')

# Form for sharing a folder with a contact and setting permissions
class ShareFolderForm(FlaskForm):
    directory = SelectField(
        'Directory',
        validators=[InputRequired()],  # Folder selection is required
        coerce=int
    )
    user = SelectField(
        'User',
        validators=[InputRequired()],  # User selection is required
        coerce=int
    )
    permissions = SelectField(
        'Permissions',
        choices=[  # Dropdown choices for permissions
            ('delete_add_download', 'Delete, Add, Download'),
            ('delete_add', 'Delete, Add'),
            ('delete_download', 'Delete, Download'),
            ('add_download', 'Add, Download'),
            ('delete', 'Delete Only'),
            ('add', 'Add Only'),
            ('download', 'Download Only'),
            ('none', 'No Permissions')
        ],
        validators=[InputRequired()]  # Permission selection is required
    )
    submit = SubmitField('Share Folder')  # Submit button

# Double Authentificator class
class TwoFactorForm(FlaskForm):
    token = StringField('2FA Code', validators=[InputRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify')

########################### UTILS ####################################################################################
# Function to check allowed file extensions
def allowed_file(filename):
    # Check for a valid extension
    if not ('.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']) or not is_safe_name(filename):
        return False

    # Ensure the filename is secure
    return secure_filename(filename) == filename

def is_safe_name(name):
    # Disallow control characters and unsafe characters
    invalid_patterns = [r'[\x00-\x1F]', r'[:;|<>]', r'\.\.', r'[/\\]', r'%00']
    for pattern in invalid_patterns:
        if re.search(pattern, name):
            return False
    return True

# Final file upload function with encryption
def handle_file_upload(uploaded_file, directory_id, owner_id, is_shared=False):
    original_filename = secure_filename(uploaded_file.filename)

    if not allowed_file(original_filename):
        log_action("file.upload_failed",
                   user_id=current_user.id,
                   details=f"unauthorized file type : file={original_filename}",
                   severity="WARNING")
        flash("File type not allowed.", "danger")
        return False

    size = request.content_length
    # Verification of file size
    if size is None or size > app.config['MAX_CONTENT_LENGTH']:
        log_action("file.upload_failed",
                   user_id=current_user.id,
                   details=f"unauthorized file size: {uploaded_file.content_length}",
                   severity="WARNING")
        flash("File is too large. Max size is 16MB.", "danger")
        return False

    directory_meta = DirectoryMetadata.query.filter_by(id=directory_id).first()
    if not directory_meta:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"metadata for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't access target directory. Directory is corrupted or doesn't exist.", "danger")
        return False

    dir_name_enc = directory_meta.dir_name_enc
    user_dir_path = _safe_storage_path(owner_id, dir_name_enc)
    os.makedirs(user_dir_path, exist_ok=True)

    if is_shared:
        if not User.query.filter_by(id=owner_id).first():
            log_action("system.metadata_missing",
                       user_id=current_user.id,
                       details=f"owner={owner_id} not found for directory={directory_meta.original_dir_name} (ID: {directory_id})",
                       severity="ERROR")
            flash("Shared folder's owner not found. Couldn't upload to this folder.", "danger")
            return False

        shared_folder = SharedFolder.query.filter_by(
            directory_id=directory_meta.id,
            owner_id=owner_id,
            shared_with_user_id=current_user.id
        ).first()

        if not shared_folder or 'add' not in shared_folder.permissions.split('_'):
            log_action("security.upload_denied",
                       user_id=current_user.id,
                       details=f"user={current_user.username} not allowed to add files to directory={directory_meta.original_dir_name} (ID: {directory_id})",
                       severity="WARNING")
            flash("You do not have permission to upload to this folder.", "danger")
            return False

    ciphertext = uploaded_file.read()

    iv_b64 = request.form.get('iv')
    salt_b64 = request.form.get('salt')
    argon_time = request.form.get('argon_time', type=int)
    argon_mem = request.form.get('argon_mem', type=int)
    argon_parallelism = request.form.get('argon_parallelism', type=int)

    if not iv_b64 or not salt_b64 or argon_time is None or argon_mem is None or argon_parallelism is None:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"missing encryption metadata for file={original_filename}",
                   severity="ERROR")
        flash("Could not upload safely the file. Do not try again.", "danger")
        return False

    iv = base64.b64decode(iv_b64)
    salt = base64.b64decode(salt_b64)

    if len(iv) != 12 or not (16 <= len(salt) <= 64):
        flash("Encryption metadata failed policy checks.", "danger")
        return False
    if not (1 <= argon_time <= 10) or not (2**15 <= argon_mem <= 2**20) or not (1 <= argon_parallelism <= 8):
        flash("Argon2 parameters are outside allowed range.", "danger")
        return False

    masked_filename = f"{uuid.uuid4().hex}.enc"
    encrypted_path = _safe_storage_path(owner_id, dir_name_enc, masked_filename)
    os.makedirs(os.path.dirname(encrypted_path), exist_ok=True)
    with open(encrypted_path, 'wb') as f:
        f.write(ciphertext)

    # Store the metadata in the DB
    metadata_record = FileMetadata(
        owner_id=owner_id,
        directory_id=directory_meta.id,
        filename_enc=masked_filename,
        original_filename=original_filename,
        salt=salt,
        iv=iv,
        cipher="AES-GCM-256",
        argon_time=argon_time,
        argon_mem=argon_mem,
        argon_parallelism=argon_parallelism,
    )
    db.session.add(metadata_record)
    db.session.commit()

    log_action(
        action="file.upload_success",
        user_id=current_user.id,
        details=f"file={original_filename}, directory={directory_meta.original_dir_name} (ID: {directory_id})",
        severity="INFO",
    )
    return True

def log_action(action, user_id=None, ip=None, details="", severity=None):
    redacted_details = sanitize_log_details(details)
    new_log = Log(
        action=action,
        user_id=user_id,
        ip_address=ip or request.remote_addr,
        details=redacted_details,
        severity=severity
    )
    db.session.add(new_log)
    db.session.commit()

def get_original_filename(user_id, filename_enc, default="Encrypted file"):
    metadata_record = FileMetadata.query.filter_by(owner_id=user_id, filename_enc=filename_enc).first()
    if metadata_record:
        return metadata_record.original_filename
    return default

def get_original_directory_name(user_id, dir_name_enc, default="Encrypted directory"):
    dir_metadata = DirectoryMetadata.query.filter_by(owner_id=user_id, dir_name_enc=dir_name_enc).first()
    if dir_metadata:
        return dir_metadata.original_dir_name
    return default

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def two_factor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('2fa_verified'):
            return redirect(url_for('two_factor'))
        return f(*args, **kwargs)
    return decorated_function

def create_admin():
    with app.app_context():
        username = input("Enter admin username: ").strip()

        if User.query.filter_by(username=username).first():
            print("Username already exists.")
            return

        while True:
            password = getpass.getpass("Enter admin password: ")
            confirm = getpass.getpass("Confirm admin password: ")
            valid, msg = validate_password_strength(password)

            if password != confirm:
                print("Passwords don't match. Try again.")
            elif not valid:
                print(f"[ERROR] {msg}")
            else:
                break

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        totp_secret = pyotp.random_base32()

        admin_user = User(username=username, password=hashed_pw, role='admin', totp_secret=totp_secret)
        db.session.add(admin_user)
        db.session.commit()

        # Generate QR
        issuer_name = "SECI_Files"
        otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name=issuer_name)
        shown = show_qr_popup_image(otp_uri)  # try GUI popup
        if not shown:
            # Fallback: ASCII QR in terminal
            print_qr_ascii(otp_uri)

        # Always print the URI as a final fallback / manual entry
        print("\n✅ Admin created. Open your authenticator and scan the QR (or paste the URI).")

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{},.?/]", password):
        return False, "Password must contain at least one special character."
    return True, ""

def verify_recaptcha():
    recaptcha_response = request.form.get('g-recaptcha-response')
    if not recaptcha_response:
        flash("Please complete the reCAPTCHA.", 'warning')
        return False

    try:
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={
                'secret': app.config['RECAPTCHA_SECRET_KEY'],
                'response': recaptcha_response},
            timeout=5)
        result = response.json()
        return result.get('success', False)
    except requests.Timeout:
        current_app.logger.warning("reCAPTCHA verify timed out")
        return False
    except requests.RequestException as e:
        current_app.logger.warning(f"reCAPTCHA error: {e}")
        return False


# Redact a string keeping first and last character if length > 2
def redact_string(s):
    if not s or len(s) <= 2:
        return '*' * len(s)
    return s[0] + '*' * (len(s) - 2) + s[-1]

# Redact filename but keep extension
def redact_filename(filename):
    if '.' in filename:
        name, ext = filename.rsplit('.', 1)
        return redact_string(name) + '.' + ext
    return redact_string(filename)

# Replace sensitive patterns in log details
def sanitize_log_details(details):
    # Replace usernames (example: user=JohnDoe)
    details = re.sub(r"user=([^\s,]+)", lambda m: f"user={redact_string(m.group(1))}", details)

    # Replace directory names (directory=Payroll)
    details = re.sub(r"directory=([^\s,]+)", lambda m: f"directory={redact_string(m.group(1))}", details)

    # Replace filenames (file=secret.pdf)
    details = re.sub(r"file=([^\s,]+)", lambda m: f"file={redact_filename(m.group(1))}", details)

    return details

def _realpath(path: str) -> str:
    return os.path.realpath(path)

def _uploads_root() -> str:
    return os.path.realpath(current_app.config['UPLOAD_FOLDER'])

def _validate_dir_token(token: str) -> None:
    if not DIR_TOKEN_RE.fullmatch(token or ""):
        abort(400, description="Invalid directory token")

def _validate_file_token(token: str) -> None:
    if not FILE_TOKEN_RE.fullmatch(token or ""):
        abort(400, description="Invalid file token")

def _safe_storage_path(owner_id: int, dir_token: str, file_token: str | None = None) -> str:
    """
    Build a path under uploads/<owner_id>/<dir_token>[/<file_token>] safely.
    - Validates tokens (rejects traversal like ../../)
    - Uses safe_join and realpath boundary check
    """
    _validate_dir_token(dir_token)
    if file_token is not None:
        _validate_file_token(file_token)

    base = _uploads_root()
    # safe_join returns None if it can't build a safe path
    candidate = safe_join(base, str(owner_id), dir_token, *([file_token] if file_token else []))
    if candidate is None:
        abort(400, description="Invalid path")

    real = os.path.realpath(candidate)
    if not (real == base or real.startswith(base + os.sep)):
        abort(400, description="Path escape detected")

    return real

def _is_within(base: str, target: str) -> bool:
    base = _realpath(base)
    target = _realpath(target)
    return target == base or target.startswith(base + os.sep)

def _overwrite_file(path: str, passes: int) -> None:
    """Overwrite a regular file with random bytes and a final zero pass."""
    size = os.path.getsize(path)
    # open in r+b so we don't truncate
    with open(path, "r+b", buffering=0) as f:
        # random passes
        for _ in range(passes):
            f.seek(0)
            remaining = size
            while remaining > 0:
                n = min(app.config['_CHUNK'], remaining)
                f.write(os.urandom(n))
                remaining -= n
            f.flush()
            os.fsync(f.fileno())
        # final zeros pass
        f.seek(0)
        zero = b"\x00" * app.config['_CHUNK']
        remaining = size
        while remaining > 0:
            n = min(app.config['_CHUNK'], remaining)
            f.write(zero[:n])
            remaining -= n
        f.flush()
        os.fsync(f.fileno())

def secure_remove(path: str, base_root: str, passes: int = 3) -> None:
    """
    Best-effort secure delete.
      - Works on files or directories (recursive).
      - Skips symlinks (does not follow).
      - Refuses to delete outside base_root.
    """
    if not _is_within(base_root, path):
        raise RuntimeError("Refusing to delete outside uploads root")

    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return True

    # Symlink
    if stat.S_ISLNK(st.st_mode):
        try:
            os.unlink(path);
            return True
        except FileNotFoundError:
            return True
        except Exception:
            return False

    # Regular file
    if stat.S_ISREG(st.st_mode):
        try:
            _overwrite_file(path, passes)
        except Exception:
            # If overwrite fails, still try to remove
            pass

        # Break directory entry linkage (rename), then unlink
        try:
            rand = f".{uuid.uuid4().hex}.del"
            tmp = os.path.join(os.path.dirname(path), rand)
            try: os.replace(path, tmp); path = tmp
            except Exception: pass
            os.remove(path)
            try: os.sync()
            except Exception: pass
            return True
        except Exception:
            return False

    # Directory (recursive, bottom-up)
    if stat.S_ISDIR(st.st_mode):
        ok = True
        for root, dirs, files in os.walk(path, topdown=False, followlinks=False):
            for name in files:
                ok &= secure_remove(os.path.join(root, name), base_root, passes)
                for dname in dirs:
                    dpath = os.path.join(root, dname)
                    try:
                        dst = os.lstat(dpath)
                        if stat.S_ISLNK(dst.st_mode):
                            try:
                                os.unlink(dpath)
                            except Exception:
                                ok = False
                        else:
                            try:
                                os.rmdir(dpath)
                            except Exception:
                                ok = False
                    except FileNotFoundError:
                        pass
            try:
                os.rmdir(path)
                return ok
            except Exception:
                return False

    # Other file types (FIFO, socket, device): just unlink best-effort
    try:
        os.unlink(path); return True
    except Exception:
        return False

def show_qr_popup_image(data: str) -> bool:
    try:
        import tkinter as tk
        from PIL import ImageTk
    except Exception:
        return False
    img = qrcode.make(data)  # PIL.Image
    root = tk.Tk()
    root.title("Scan this QR with your Authenticator")
    # Convert PIL to Tk image
    tk_img = ImageTk.PhotoImage(img)
    lbl = tk.Label(root, image=tk_img)
    lbl.pack(padx=10, pady=10)
    # Add the URI as a fallback text (selectable)
    txt = tk.Text(root, height=3, width=80)
    txt.insert("1.0", data)
    txt.config(state="disabled")
    txt.pack(padx=10, pady=(0, 10))
    try:
        root.mainloop()
        return True
    except Exception:
        return False

def print_qr_ascii(data: str) -> None:
    """Render a QR code in the terminal using block characters."""
    qr = qrcode.QRCode(border=1, box_size=1)
    qr.add_data(data)
    qr.make(fit=True)
    matrix = qr.get_matrix()  # list[list[bool]]
    # Use double blocks for better aspect ratio
    black, white = "██", "  "
    print()
    for row in matrix:
        print("  " + "".join(black if cell else white for cell in row))
    print()
########################## ROUTES ##################################################################################
# Function to load the user based on the session (required by Flask-Login)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Retrieve the user from the database

# Route to display all users except the current logged-in user
@app.route('/users', methods=['GET'])
@login_required
def users():
    all_users = User.query.filter(User.id != current_user.id).all()  # Retrieve all users except the current user
    return render_template('users.html', users=all_users)  # Render the user's template

# Home route that is shown when the user first accesses the site
@app.route('/')
def home():
    return render_template('home.html')  # Render the home page

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("3 per 120 seconds", key_func=get_remote_address, methods=["POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        if not verify_recaptcha():
            flash('reCAPTCHA verification failed. Please try again.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            session.permanent = True  # Enable session timeout tracking
            session['login_time'] = int(time.time())
            session['last_seen'] = int(time.time())  # for inactivity timeout, if you use it

            log_action("auth.login_success",
                       user_id=user.id,
                       severity="INFO")
            return redirect(url_for('dashboard'))
        else:
            log_action("auth.login_failed",
                       details=f"user={form.username.data}",
                       severity="WARNING")
            flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form, config=app.config)

# Route for logging out
@app.route('/logout')
@login_required
def logout():
    logout_user()  # Log the user out
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))  # Redirect to the login page

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()  # Create a registration form instance

    if form.validate_on_submit():  # If the form is submitted and validated
        if not verify_recaptcha():
            flash('reCAPTCHA verification failed. Please try again.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hash the password
        new_user = User(username=form.username.data, password=hashed_password)  # Create a new user

        totp_secret = pyotp.random_base32()
        new_user.totp_secret = totp_secret
        issuer_name = "SECI_Files"  # Name of the app

        # URI TOTP standard
        otp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=form.username.data, issuer_name=issuer_name)

        # Generate QRCode
        qr_img = qrcode.make(otp_uri)
        buf = BytesIO()
        qr_img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        db.session.add(new_user)  # Add the user to the database
        db.session.commit()  # Commit the changes to the database

        log_action("auth.register_success",
                   user_id=new_user.id,
                   details=f"user={new_user.username}",
                   severity="INFO")
        flash(f"Account created for {form.username.data}!", 'success')  # Show a success message
        return render_template('register.html', form=form, qr_code=qr_code_b64)
    return render_template('register.html', form=form, config=app.config)  # Render the registration page

@app.route('/2fa', methods=['GET', 'POST'])
@login_required
@limiter.limit("5 per 5 minutes", methods=["POST"])
def two_factor():
    form = TwoFactorForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(current_user.totp_secret)
        if totp.verify(form.token.data, valid_window=1):
            session['2fa_verified'] = True
            return redirect(url_for('dashboard'))
        flash("Invalid 2FA code", "danger")
    return render_template('2fa.html', form=form)


# Route for the user dashboard, where they can manage files, folders, contacts, etc.
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
@two_factor_required
def dashboard():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))  # Get the path to the user's folder
    os.makedirs(user_folder, exist_ok=True)  # Create the user's folder if it doesn't exist

    # Instantiate WTF-forms
    upload_form = UploadForm()
    create_form = CreateDirectoryForm()
    share_form = ShareFolderForm()

    user_directories = DirectoryMetadata.query.filter_by(owner_id=current_user.id).all()

    # Populate form choices
    upload_form.directory.choices = [(str(dir_meta.id), dir_meta.original_dir_name) for dir_meta in user_directories]

    # List all shared directories with this user with 'add' permission
    shared_addable = SharedFolder.query.filter_by(shared_with_user_id=current_user.id).all()

    for sf in shared_addable:
        if 'add' in sf.permissions.split('_') and sf.directory:
            label = f"{sf.directory.original_dir_name} (shared by {sf.owner.username})"
            value = f"shared::{sf.owner_id}::{sf.directory_id}"
            upload_form.directory.choices.append((value, label))

    # Handle file upload form
    if upload_form.validate_on_submit() and 'file' in request.files:
        uploaded_file = upload_form.file.data
        selected_directory = upload_form.directory.data
        is_shared = selected_directory.startswith(f"shared::")

        try:
            if is_shared:
                _, owner_id_str, directory_id_str = selected_directory.split("::")
                owner_id = int(owner_id_str)
                directory_id = int(directory_id_str)
            else:
                owner_id = current_user.id
                directory_id = int(selected_directory)
        except Exception as e:
            log_action("file.upload_failed",
                       user_id=current_user.id,
                       details=f"unexpected error: {str(e)}",
                       severity="ERROR")
            flash("Invalid directory selected.", "danger")
            return redirect(url_for('dashboard'))

        if uploaded_file.filename:
            if handle_file_upload(uploaded_file, directory_id, owner_id, is_shared):
                flash(f"File '{uploaded_file.filename}' uploaded successfully !", "success")
            else:
                flash("File upload failed. Please check the file and try again.", "danger")
        else:
            log_action("file.upload_failed",
                       user_id=current_user.id,
                       details="no file supplied",
                       severity="ERROR")
            flash("No file selected for upload.", "warning")

    # Handle create directory form
    elif create_form.validate_on_submit() and 'create_directory' in request.form:
        directory_name = create_form.directory_name.data.strip()

        if not directory_name:
            log_action("directory.create_failed",
                       user_id=current_user.id,
                       details="no directory name supplied",
                       severity="ERROR")
            flash("Directory name cannot be empty!", "warning")

        if not is_safe_name(directory_name):
            log_action("directory.crewate_failed",
                       user_id=current_user.id,
                       details="unsafe directory name supplied : {directory_name}",
                       severity="WARNING")
            flash("Directory name contains forbidden characters.", "danger")

        existing = DirectoryMetadata.query.filter_by(owner_id=current_user.id, original_dir_name=directory_name).first()

        if existing:
            log_action("directory.create_failed",
                       user_id=current_user.id,
                       details=f"duplicate directory name: directory={directory_name}",
                       severity="WARNING")
            flash(f"A directory named '{directory_name}' already exists.", "warning")
            return redirect(url_for('dashboard'))

        dir_name_enc = uuid.uuid4().hex
        new_dir_meta = DirectoryMetadata(
            owner_id=current_user.id,
            original_dir_name=directory_name,
            dir_name_enc=dir_name_enc
        )
        try:
            db.session.add(new_dir_meta)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash(f"A directory named '{directory_name}' already exists.", "warning")
            log_action("directory.create_failed",
                       user_id=current_user.id,
                       details=f"duplicate caught at commit: directory={directory_name}",
                       severity="WARNING")
            return redirect(url_for('dashboard'))

        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(current_user.id))
        new_directory_path = os.path.join(user_folder, dir_name_enc)

        try:
            os.makedirs(new_directory_path, exist_ok=False)
        except FileExistsError:
            db.session.delete(new_dir_meta)
            db.session.commit()
            flash("Failed to create the directory on disk. Please retry.", "danger")
            log_action("directory.create_failed",
                       user_id=current_user.id,
                       details=f"filesystem mkdir collision for dir_token={dir_name_enc}",
                       severity="ERROR")

            return redirect(url_for('dashboard'))
        except OSError as e:
            db.session.delete(new_dir_meta)
            db.session.commit()
            flash("Error creating directory on disk.", "danger")
            log_action("directory.create_failed",
                       user_id=current_user.id,
                       details=f"oserror creating directory: {e}",
                       severity="ERROR")
            return redirect(url_for('dashboard'))

        log_action("directory.create_success",
                   user_id=current_user.id,
                   details=f"directory={directory_name}",
                   severity="INFO")
        flash(f"Directory '{directory_name}' created successfully!", "success")
        return redirect(url_for('dashboard'))

    contact_requests = ContactRequest.query.filter_by(receiver_id=current_user.id, status='pending').all()  # Get requests where the user is the receiver

    # Get the user's contacts
    contacts = Contact.query.filter_by(user_id=current_user.id).all()  # Get the user's contacts from the database

    # Get shared folders (both shared with the user and by the user)
    shared_with_me = SharedFolder.query.filter_by(shared_with_user_id=current_user.id).all()  # Folders shared with the user
    shared_by_me = SharedFolder.query.filter_by(owner_id=current_user.id).all()  # Folders shared by the user

    # Render the dashboard template with necessary data
    return render_template(
        'dashboard.html',
        upload_form=upload_form,
        directory_form=create_form,
        share_form=share_form,
        directories=user_directories,
        user_id=current_user.id,
        contact_requests=contact_requests,
        contacts=contacts,
        shared_with_me=shared_with_me,
        shared_by_me=shared_by_me
    )

# Route for viewing files in a specific directory
@app.route('/dashboard/<int:directory_id>', methods=['GET', 'POST'])
@login_required
@two_factor_required
def view_directory(directory_id):
    directory_meta = DirectoryMetadata.query.filter_by(id=directory_id).first()

    if not directory_meta:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"metadata for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't access target directory. Directory corrupted or doesn't exist.", "danger")
        return redirect(url_for('dashboard'))

    # Determine if current user is owner or has access
    is_owner = directory_meta.owner_id == current_user.id
    has_shared_access = SharedFolder.query.filter_by(
        directory_id=directory_id,
        shared_with_user_id=current_user.id
    ).first()

    if not is_owner and not has_shared_access:
        log_action("security.access_denied",
                   user_id=current_user.id,
                   details=f"access denied to directory={directory_meta.original_dir_name} (ID: {directory_id}) for user={current_user.username}",
                   severity="WARNING")
        flash("You do not have the permission to access this directory.", "danger")
        return redirect(url_for('dashboard'))

    directory_path = _safe_storage_path(directory_meta.owner_id, directory_meta.dir_name_enc)

    if not os.path.exists(directory_path) or not os.path.isdir(directory_path):
        log_action("system.path_missing",
                   user_id=current_user.id,
                   details=f"path missing for directory ID {directory_id}",
                   severity="ERROR")
        flash("Couldn't access target directory. Directory is corrupted or doesn't exist.", "danger")
        return redirect(url_for('dashboard'))

    displayed_files = []
    for filename in os.listdir(directory_path):
        if FILE_TOKEN_RE.fullmatch(filename):
            metadata = FileMetadata.query.filter_by(
                owner_id=directory_meta.owner_id, filename_enc=filename
            ).first()
            if metadata:
                displayed_files.append({
                    'id': metadata.id,
                    'enc_name': filename,
                    'original_filename': metadata.original_filename
                })

    return render_template(
        'view_directory.html',
        directory_name=directory_meta.original_dir_name,
        directory_id=directory_id,
        files=displayed_files)

@app.route('/delete/<int:directory_id>/<filename>', methods=['POST'])
@login_required
@two_factor_required
def delete_file(directory_id, filename):
    directory_meta = DirectoryMetadata.query.filter_by(id=directory_id).first()
    if not directory_meta:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"metadata for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't access shared folder. Directory is corrupted or doesn't exist.", "danger")
        return redirect(url_for('dashboard'))

    owner_id = directory_meta.owner_id
    dir_name_enc = directory_meta.dir_name_enc
    is_shared = current_user.id != owner_id
    original_filename = get_original_filename(owner_id, filename)
    uploads_root = app.config['UPLOAD_FOLDER']

    # Determine if this is a shared folder context
    if is_shared:
        shared_folder = SharedFolder.query.filter_by(
            directory_id=directory_id,
            owner_id=owner_id,
            shared_with_user_id=current_user.id
        ).first()

        if not shared_folder or 'delete' not in shared_folder.permissions.split('_'):
            flash("You don't have permission to delete files in this directory.", "danger")
            log_action("security.delete_denied",
                       user_id=current_user.id,
                       details=f"unauthorized delete attempt of file={original_filename} in directory={directory_meta.original_dir_name} (ID: {directory_id}) for user={current_user.username}",
                       severity="WARNING")
            return redirect(url_for('view_shared_folder', owner_id=owner_id, directory_id=directory_id))

    _validate_file_token(filename)
    file_path = _safe_storage_path(owner_id, dir_name_enc, filename)
    uploads_root = _uploads_root()  # keep secure_remove boundary exact

    if os.path.exists(file_path):
        try:
            secure_remove(file_path, base_root=uploads_root, passes=3)

            # Delete associated metadata if it exists
            metadata_record = FileMetadata.query.filter_by(owner_id=owner_id, filename_enc=filename).first()

            if metadata_record:
                db.session.delete(metadata_record)
                db.session.commit()

            flash(f"File '{original_filename}' deleted successfully!", "success")
            log_action("file.delete_success",
                       user_id=current_user.id,
                       details=f"file={original_filename}, directory={directory_meta.original_dir_name} (ID: {directory_id})",
                       severity="INFO")
        except Exception as e:
            flash(f"Failed to delete file: {str(e)}", "danger")
            log_action("file.delete_failed",
                       user_id=current_user.id,
                       details=f"error={str(e)}",
                       severity="ERROR")
    else:
        flash("File not found.", "danger")
        log_action("file.delete_failed",
                   user_id=current_user.id,
                   details=f"file={original_filename} not found in directory={directory_meta.original_dir_name} (ID: {directory_id})",
                   severity="ERROR")

    # Redirect to appropriate view
    if is_shared:
        return redirect(url_for('view_shared_folder', owner_id=owner_id, directory_id=directory_id))
    else:
        return redirect(url_for('view_directory', directory_id=directory_id))

@app.route('/delete_directory/<directory_id>', methods=['POST'])
@login_required
@two_factor_required
def delete_directory(directory_id):
    directory_meta = DirectoryMetadata.query.filter_by(id=directory_id).first()
    if not directory_meta:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"metadata for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't delete this directory. Directory is corrupted or doesn't exist.", "danger")
        return redirect(url_for('dashboard'))

    # Check ownership
    if directory_meta.owner_id != current_user.id:
        flash("You do not own this directory. Couldn't delete directory.", "danger")
        log_action("security.delete_denied",
                   user_id=current_user.id,
                   details=f"attempted to delete unowned directory={directory_meta.original_dir_name} (ID: {directory_id}) by user={current_user.username}",
                   severity="WARNING")
        return redirect(url_for('dashboard'))

    # Check if the directory is still shared with others
    is_shared = SharedFolder.query.filter_by(directory_id=directory_id).first()
    if is_shared:
        flash("You cannot delete a directory that is still shared. Unshare it first.", "warning")
        log_action("directory.delete_failed",
                   user_id=current_user.id,
                   details=f"directory={directory_meta.original_dir_name} (ID: {directory_id}) is still shared",
                   severity="WARNING")
        return redirect(url_for('dashboard'))

    # Check if the directory is empty
    uploads_root = app.config['UPLOAD_FOLDER']
    dir_path = os.path.join(uploads_root, str(current_user.id), directory_meta.dir_name_enc)

    if not os.path.exists(dir_path):
        flash("Couldn't delete directory. Directory is corrupted or doesn't exist.", "danger")
        log_action("system.path_missing",
                   user_id=current_user.id,
                   details=f"path for directory={directory_meta.original_dir_name} (ID: {directory_id}) is missing",
                   severity="ERROR")
        return redirect(url_for('dashboard'))

    try:
        # Shred all contents + remove directory
        removed = secure_remove(dir_path, base_root=uploads_root, passes=3)
        if not removed and os.path.isdir(dir_path):
            # short retry loop in case a handle (e.g., thumbnailer) had it open
            for _ in range(3):
                try:
                    os.rmdir(dir_path)
                    break
                except OSError:
                    time.sleep(0.1)
            # last resort: remove empty tree (dirs only)
            if os.path.isdir(dir_path):
                shutil.rmtree(dir_path, ignore_errors=True)

        # Clean DB metadata for files in this directory
        FileMetadata.query.filter_by(owner_id=current_user.id, directory_id=directory_id).delete()

        db.session.delete(directory_meta)
        db.session.commit()

        flash("Directory deleted successfully.", "success")
        log_action("directory.delete_success",
                   user_id=current_user.id,
                   details=f"directory={directory_meta.original_dir_name} (ID: {directory_id})",
                   severity="INFO")
    except Exception as e:
        flash(f"Error deleting directory.", "danger")
        log_action("directory.delete_failed",
                   user_id=current_user.id,
                   details=f"exception deleting directory={directory_meta.original_dir_name} (ID: {directory_id}): {str(e)}",
                   severity="ERROR")

    # Redirect back to the dashboard after attempting directory deletion
    return redirect(url_for('dashboard'))

@app.route('/send_contact_request/<int:receiver_id>', methods=['POST'])
@login_required
@two_factor_required
def send_contact_request(receiver_id):
    # Prevent users from adding themselves as contacts
    if receiver_id == current_user.id:
        flash('You cannot add yourself as a contact.', 'warning')
        return redirect(url_for('users'))  # Redirect to the user list page if the user tries to add themselves

    # Retrieve the user who is the intended recipient of the contact request
    receiver = User.query.get(receiver_id)
    if not receiver:
        log_action("contact.request_denied",
                   user_id=current_user.id,
                   details=f"contact with ID={receiver_id} not found",
                   severity="ERROR")
        flash("Target user not found. Couldn't send request", 'danger')  # Notify if the receiver user is not found
        return redirect(url_for('users'))  # Redirect to the user list page if the receiver is not found

    # If you already are contacts, don’t send a request
    already_contact = Contact.query.filter_by(user_id=current_user.id, contact_id=receiver_id).first()
    if already_contact:
        flash('You are already contacts.', 'info')
        return redirect(url_for('users'))

    # If there’s an incoming pending request from them to you, just tell the user to accept it (or auto-accept)
    incoming = ContactRequest.query.filter_by(sender_id=receiver_id, receiver_id=current_user.id,
                                              status='pending').first()
    if incoming:
        flash(f"{receiver.username} already sent you a request. Check your requests.", 'info')
        return redirect(url_for('dashboard'))

    # Look for an existing request from you to them (any status)
    existing = ContactRequest.query.filter_by(sender_id=current_user.id, receiver_id=receiver_id).first()

    if existing:
        if existing.status == 'pending':
            flash('Contact request already sent and is pending.', 'info')
            return redirect(url_for('users'))
        elif existing.status == 'accepted':
            flash('You are already contacts.', 'info')
            return redirect(url_for('users'))
        elif existing.status == 'rejected':
            # <— KEY PART: reuse the same row
            existing.status = 'pending'
            db.session.commit()
            log_action("contact.request_resent",
                       user_id=current_user.id,
                       details=f"request resent to user={receiver.username}",
                       severity="INFO")
            flash('Contact request resent.', 'success')
            return redirect(url_for('dashboard'))
    else:
        # No prior row — create a fresh one
        req = ContactRequest(sender_id=current_user.id, receiver_id=receiver_id, status='pending')
        db.session.add(req)
        db.session.commit()
        log_action("contact.request_success",
                   user_id=current_user.id,
                   details=f"request sent to user={receiver.username}",
                   severity="INFO")
        flash('Contact request sent successfully.', 'success')
        return redirect(url_for('dashboard'))

@app.route('/respond_contact_request/<int:request_id>', methods=['POST'])
@login_required
@two_factor_required
def respond_contact_request(request_id):
    action = request.form.get('action')  # Retrieve the action chosen by the user (either 'accept' or 'reject')
    contact_request = ContactRequest.query.get(request_id)

    # Ensure that the contact request exists and that the user is the intended recipient
    if not contact_request or contact_request.receiver_id != current_user.id:
        log_action(action="contact.request_denied",
                   user_id=current_user.id,
                   details=f"contact with ID={request_id} not found",
                   severity="ERROR")
        flash("Target user couldn't be found.", 'danger')  # Notify if the request is invalid or not for the current user
        return redirect(url_for('dashboard'))  # Redirect to the dashboard in case of an invalid request

    if action == 'accept':
        # Create two new contact entries to establish the contact relationship
        new_contact_1 = Contact(user_id=current_user.id, contact_id=contact_request.sender_id)
        new_contact_2 = Contact(user_id=contact_request.sender_id, contact_id=current_user.id)
        db.session.add(new_contact_1)
        db.session.add(new_contact_2)
        contact_request.status = 'accepted'  # Mark the request as accepted
        log_action(action="contact.request_accepted",
                   user_id=current_user.id,
                   details=f"request accepted from user={contact_request.sender.username}",
                   severity="INFO")
        flash('Contact request accepted.', 'success')  # Notify the user that the request was accepted
    elif action == 'reject':
        contact_request.status = 'rejected'  # Mark the request as rejected
        log_action(action="contact.request_rejected",
                   user_id=current_user.id,
                   details=f"request rejected from user={contact_request.sender.username}",
                   severity="INFO")
        flash('Contact request rejected.', 'info')  # Notify the user that the request was rejected
    else:
        log_action(action="contact.request_denied",
                   user_id=current_user.id,
                   details="invalid contact request action",
                   severity="ERROR")
        flash('Invalid action.', 'danger')  # Notify if the action is invalid

    db.session.commit()  # Commit the changes to the database
    return redirect(url_for('dashboard'))  # Redirect back to the dashboard after responding to the request


@app.route('/delete_contact/<int:contact_id>', methods=['POST'])
@login_required
@two_factor_required
def delete_contact(contact_id):
    # Contact row from me -> them
    link = Contact.query.filter_by(user_id=current_user.id, contact_id=contact_id).first()
    # And the reciprocal row from them -> me
    link_back = Contact.query.filter_by(user_id=contact_id, contact_id=current_user.id).first()

    if not link:
        log_action("contact.delete_failed",
                   user_id=current_user.id,
                   details=f"contact with ID={contact_id} not found",
                   severity="ERROR")
        flash('Unauthorized action or contact not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Capture the other user's username for logging *before* we delete rows
    other_user = User.query.get(contact_id)
    other_name = other_user.username if other_user else f"id={contact_id}"

    # Revoke any shares in both directions
    SharedFolder.query.filter_by(owner_id=current_user.id,
                                 shared_with_user_id=contact_id).delete(synchronize_session=False)
    SharedFolder.query.filter_by(owner_id=contact_id,
                                 shared_with_user_id=current_user.id).delete(synchronize_session=False)

    # Delete contact requests between the two users (any status, any direction)
    ContactRequest.query.filter(
        or_(
            and_(ContactRequest.sender_id == current_user.id, ContactRequest.receiver_id == contact_id),
            and_(ContactRequest.sender_id == contact_id, ContactRequest.receiver_id == current_user.id),
        )
    ).delete(synchronize_session=False)

    # Delete the contact links
    db.session.delete(link)
    if link_back:
        db.session.delete(link_back)

    db.session.commit()

    log_action("contact.delete_success",
               user_id=current_user.id,
               details=f"user={other_name} contact deleted",
               severity="INFO")
    flash('Contact removed successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/share_folder', methods=['GET', 'POST'])
@login_required
@two_factor_required
def share_folder():
    share_form = ShareFolderForm()

    # Populate form dropdowns
    share_form.directory.choices = [
        (dir_meta.id, dir_meta.original_dir_name)
        for dir_meta in DirectoryMetadata.query.filter_by(owner_id=current_user.id).all()]

    share_form.user.choices = [
        (c.contact_id, c.contact.username)
        for c in Contact.query.filter_by(user_id=current_user.id).all()]

    if share_form.validate_on_submit():
        directory_id = share_form.directory.data
        selected_user_id = share_form.user.data
        permissions = share_form.permissions.data

        # Fetch directory metadata
        directory_meta = DirectoryMetadata.query.filter_by(id=directory_id, owner_id=current_user.id).first()
        if not directory_meta:
            log_action("system.metadata_missing",
                       user_id=current_user.id,
                       details=f"metadata for directory ID {directory_id} is missing",
                       severity="ERROR")
            flash("Couldn't share directory. Directory is corrupted or doesn't exist.", "danger")
            return redirect(url_for('dashboard'))

        # Double check contact relationship
        contact_exists = Contact.query.filter_by(user_id=current_user.id, contact_id=selected_user_id).first()
        if not contact_exists:
            log_action("share.denied",
                       user_id=current_user.id,
                       details=f"Attempted to share with non-contact user ID={selected_user_id}",
                       severity="WARNING")
            flash("You can only share folders with your contacts.", "warning")
            return redirect(url_for('dashboard'))

        # Check if folder is already shared with contact
        already_shared = SharedFolder.query.filter_by(
            directory_id=directory_id,
            owner_id=current_user.id,
            shared_with_user_id=selected_user_id
        ).first()

        if already_shared:
            log_action("share.duplicate",
                       user_id=current_user.id,
                       details=f"directory={directory_meta.original_dir_name} (ID: {directory_id}) already shared with user ID={selected_user_id}",
                       severity="INFO")
            flash("This folder is already shared with the selected contact.", "warning")
            return redirect(url_for('dashboard'))

        # Create shared folder entry
        shared_folder = SharedFolder(
            directory_id=directory_id,
            owner_id=current_user.id,
            shared_with_user_id=selected_user_id,
            permissions=permissions
        )
        db.session.add(shared_folder)
        db.session.commit()

        log_action("share.success",
                   user_id=current_user.id,
                   details=f"directory={directory_meta.original_dir_name} (ID: {directory_id}) shared with user ID={selected_user_id}",
                   severity="INFO")
        flash(f"Directory '{directory_meta.original_dir_name}' shared successfully.", "success")
        return redirect(url_for('dashboard'))

    else:
        flash("Invalid form submission.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/shared_by_me', methods=['GET', 'POST'])
@login_required
@two_factor_required
def shared_by_me():
    # Retrieve all shared folders owned by the current user
    shared_folders = SharedFolder.query.filter_by(owner_id=current_user.id).all()

    # Handle POST request for deleting a shared folder
    if request.method == 'POST':
        shared_folder_id = request.form.get('directory_id')  # Retrieve the folder ID to delete

        # Validate ID
        try:
            shared_folder_id = int(shared_folder_id)
        except (ValueError, TypeError):
            flash("Invalid directory ID.", "danger")
            log_action("share.unshare_failed",
                       user_id=current_user.id,
                       details="non-integer directory ID submitted : {shared_folder_id}",
                       severity="ERROR")
            return redirect(url_for('shared_by_me'))

        folder_to_delete = SharedFolder.query.get(shared_folder_id)  # Fetch the shared folder from the database

        # Ensure that the folder to delete exists and belongs to the current user
        if folder_to_delete and folder_to_delete.owner_id == current_user.id:
            db.session.delete(folder_to_delete)  # Delete the folder from the database
            db.session.commit()  # Commit the changes to the database

            log_action("share.unshare_success",
                       user_id=current_user.id,
                       details=f"Unshared directory with ID {shared_folder_id} with user ID={folder_to_delete.shared_with_user_id}",
                       severity="INFO")
            flash("You stopped sharing this folder with your contact.", "success")  # Notify the user of successful deletion
        else:
            log_action("share.unshare_failed",
                       user_id=current_user.id,
                       details=f"Attempted unshare failed. ID={shared_folder_id} not found or not owned by user.",
                       severity="WARNING")
            flash("Unable to unshare this folder.", "danger")  # Notify the user if the deletion is not successful

        return redirect(url_for('shared_by_me'))  # Redirect back to the page displaying shared folders by the user

    # Render the template for displaying shared folders owned by the current user
    return render_template('shared_by_me.html', shared_folders=shared_folders)


@app.route('/shared_with_me', methods=['GET'])
@login_required
@two_factor_required
def shared_with_me():
    try:
        # Retrieve all shared folders that have been shared with the current user
        shared_folders = SharedFolder.query.filter(SharedFolder.shared_with_user_id == current_user.id).all()

        # Render the template for displaying the shared folders
        return render_template('shared_with_me.html', shared_folders=shared_folders)

    except Exception as e:
        log_action("system.error",
                   user_id=current_user.id,
                   details=f"Failed to retrieve shared folders: {str(e)}",
                   severity="ERROR")
        flash("Could not load shared folders.", "danger")
        return redirect(url_for("dashboard"))

@app.route('/view_shared_folder/<int:owner_id>/<int:directory_id>', methods=['GET'])
@login_required
@two_factor_required
def view_shared_folder(owner_id, directory_id):
    owner = User.query.filter_by(id=owner_id).first()

    if not owner:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"owner with ID {owner_id} of directory ID {directory_id} not found",
                   severity="ERROR")
        flash("Couldn't access shared folder. Directory owner not found.", 'danger')
        return redirect(url_for('shared_with_me'))

    shared_folder = SharedFolder.query.filter_by(owner_id=owner.id, directory_id=directory_id, shared_with_user_id=current_user.id).first()

    # Check if the shared folder exists and if the current user has access to it
    if not shared_folder:
        log_action("security.access_denied",
                   user_id=current_user.id,
                   details=f"access denied to directory ID {directory_id} for user={current_user.username}",
                   severity="WARNING")
        flash('Shared folder not found or you do not have permission to access it.', 'danger')
        return redirect(url_for('shared_with_me'))  # Redirect to the shared folder view if the folder is not found

    # Fetch directory metadata
    directory_meta = DirectoryMetadata.query.filter_by(id=directory_id, owner_id=owner_id).first()
    if not directory_meta:
        log_action("system.metadata_missing",
                   user_id=current_user.id,
                   details=f"metadata for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't access shared folder. Directory is corrupted or doesn't exist.", "danger")
        return redirect(url_for("shared_with_me"))

    # Retrieve the path to the shared folder on the server
    directory_path = _safe_storage_path(directory_meta.owner_id, directory_meta.dir_name_enc)

    # Check if the folder exists on the server
    if not os.path.exists(directory_path):
        log_action("system.path_missing",
                   user_id=current_user.id,
                   details=f"path for directory ID {directory_id} is missing",
                   severity="ERROR")
        flash("Couldn't access shared folder. Directory is corrupted or doesn't exist.", "danger")
        return redirect(url_for("shared_with_me"))

    # List the contents of the shared folder
    displayed_files = []
    for filename in os.listdir(directory_path):
        if FILE_TOKEN_RE.fullmatch(filename):
            metadata = FileMetadata.query.filter_by(
                owner_id=owner_id, filename_enc=filename
            ).first()
            if metadata:
                displayed_files.append({
                    'id': metadata.id,
                    'enc_name': filename,
                    'original_filename': metadata.original_filename
                })

    permissions = set(shared_folder.permissions.split('_'))

    # Render the template to display the shared folder and its contents
    return render_template(
        'view_shared_folder.html',
        files=displayed_files,
        directory_name=directory_meta.original_dir_name,
        owner_id=owner.id,
        directory_id=directory_id,
        permissions=permissions
    )

@app.route('/logs')
@login_required
@admin_required
@two_factor_required
def show_logs():
    logs = Log.query.order_by(Log.timestamp.desc()).limit(100).all()
    return render_template('logs.html', logs=logs)

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    # Flask-Limiter exposes how many seconds until the bucket resets
    seconds = (
        getattr(e, "retry_after", None) or
        getattr(getattr(e, "limit", None), "window_stats", None).reset_in
        if getattr(e, "limit", None) and getattr(e.limit, "window_stats", None) else None
    )
    try:
        seconds = int(seconds)
    except (TypeError, ValueError):
        seconds = 60  # fallback value if nothing found

    resp = make_response(render_template("429.html", seconds=seconds), 429)
    resp.headers["Retry-After"] = seconds
    return resp

@app.before_request
def enforce_absolute_timeout():
    if not current_user.is_authenticated:
        return

    now = int(time.time())
    login_ts = session.get('login_time')
    last_seen_ts = session.get('last_seen')

    # Absolute timeout
    if login_ts and (now - login_ts) > int(ABSOLUTE_SESSION_TIMEOUT.total_seconds()):
        logout_user()
        session.clear()
        flash("Your session has expired. Please log in again.", "warning")
        return redirect(url_for('login'))

    # Inactivity timeout
    if last_seen_ts and (now - last_seen_ts) > int(INACTIVE_SESSION_TIMEOUT.total_seconds()):
        logout_user()
        session.clear()
        flash("You were logged out due to inactivity.", "warning")
        return redirect(url_for('login'))

    # Update activity timestamp
    session['last_seen'] = now

@app.after_request
def add_no_cache_headers(response):
    if current_user.is_authenticated:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

@app.after_request
def add_header(response):
    if current_user.is_authenticated or request.endpoint == 'login':
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.context_processor
def inject_session_timeouts():
    return {
        'INACTIVE_SESSION_TIMEOUT': INACTIVE_SESSION_TIMEOUT,
        'ABSOLUTE_SESSION_TIMEOUT': ABSOLUTE_SESSION_TIMEOUT
    }

@app.get("/api/files/<int:file_id>/metadata")
@login_required
@two_factor_required
def get_file_meta(file_id):
    file_metadata = FileMetadata.query.filter_by(id=file_id).first_or_404()

    # Verify access : owner or shared with download permission
    dir_metadata = DirectoryMetadata.query.filter_by(id=file_metadata.directory_id).first_or_404()
    owner_id = dir_metadata.owner_id
    is_owner = (owner_id == current_user.id)
    has_shared_access = SharedFolder.query.filter_by(
        directory_id=file_metadata.directory_id,
        owner_id=owner_id,
        shared_with_user_id=current_user.id
    ).first()

    if not is_owner and (not has_shared_access or 'download' not in has_shared_access.permissions.split('_')):
        abort(403)

    return jsonify({
        "cipher": file_metadata.cipher,
        "salt": base64.b64encode(file_metadata.salt).decode(),
        "iv": base64.b64encode(file_metadata.iv).decode() if file_metadata.iv else None,
        "original_filename": file_metadata.original_filename,
        "directory_id": file_metadata.directory_id,
        "filename_enc": file_metadata.filename_enc,
        "owner_id": owner_id,
        "argon_time": file_metadata.argon_time,
        "argon_mem": file_metadata.argon_mem,
        "argon_parallelism": file_metadata.argon_parallelism
    })


@app.get("/files/<int:directory_id>/<path:filename_enc>")
@login_required
@two_factor_required
def download_ciphertext(directory_id, filename_enc):
    # Verify metadata and permissions
    dir_metadata = DirectoryMetadata.query.filter_by(id=directory_id).first_or_404()
    owner_id = dir_metadata.owner_id
    is_owner = (owner_id == current_user.id)
    has_shared_access = SharedFolder.query.filter_by(
        directory_id=directory_id,
        owner_id=owner_id,
        shared_with_user_id=current_user.id
    ).first()

    if not is_owner and (not has_shared_access or 'download' not in has_shared_access.permissions.split('_')):
        abort(403)

    # Verify token and build the path
    _validate_file_token(filename_enc)
    enc_path = _safe_storage_path(owner_id, dir_metadata.dir_name_enc, filename_enc)
    if not os.path.exists(enc_path):
        abort(404)

    return send_file(enc_path, as_attachment=True, download_name=filename_enc)

############################# RUN #####################################################################################
# Run the Flask application
if __name__ == "__main__":

    with app.app_context():
        db.create_all() # Create all database tables

        # creation automatic the user admin
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            create_admin()

    parser = argparse.ArgumentParser(description="Start the Flask application with SSL.")
    parser.add_argument('--host', default='127.0.0.1', help="Hostname to listen on.")
    parser.add_argument('--port', type=int, default=5000, help="Port to listen on.")
    parser.add_argument('--cert', help="Path to SSL certificate.")
    parser.add_argument('--key', help="Path to SSL key.")
    args = parser.parse_args()

    if not args.cert or not args.key:
        raise FileNotFoundError("Both --cert and --key arguments are required to start the application with SSL.")

    app.run(debug=False, host=args.host, port=args.port, ssl_context=(args.cert, args.key))
