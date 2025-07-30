from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import os
from google.cloud.firestore_v1.base_query import FieldFilter
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import uuid
from flask_cors import CORS
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore, storage
from dotenv import load_dotenv

import requests
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
# from twilio.rest import Client

import logging
from functools import wraps
from collections import defaultdict
import time

# Loading environment variables
try:
    load_dotenv()
    # Messaging and Email API keys
    BREVO_API_KEY = os.getenv('BREVO_API_KEY')
    TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')
    TWILIO_WHATSAPP_NUMBER = os.getenv('TWILIO_WHATSAPP_NUMBER')

    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN) if TWILIO_ACCOUNT_SID else None

    print(".env file loaded successfully")
except Exception as e:
    print(f"Warning: Could not load .env file - {e}")

# Initializing Flask app with configuration from environment
app = Flask(__name__)
CORS(app)

# Configure secret key - using environment variable or fallback for development
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'TAI_KHAMYANG_DEV_KEY_2025')
if app.secret_key == 'development-key-only-change-in-production':
    print("WARNING: Using development secret key. For production, set FLASK_SECRET_KEY in .env file")

# Configure upload folder
app.config['UPLOAD_FOLDER'] = 'static/audio'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Firebase initialization with better error handling
try:
    firebase_admin_sdk_path = os.getenv("FIREBASE_ADMIN_SDK_PATH")
    if not firebase_admin_sdk_path:
        raise ValueError("FIREBASE_ADMIN_SDK_PATH not found in environment variables")

    if not os.path.exists(firebase_admin_sdk_path):
        raise FileNotFoundError(f"Firebase admin SDK file not found at {firebase_admin_sdk_path}")

    cred = credentials.Certificate(firebase_admin_sdk_path)
    firebase_admin.initialize_app(cred, {'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET')})
    db = firestore.client()
    bucket = storage.bucket()
    print("Firebase initialized successfully")
except Exception as e:
    print(f"ERROR: Firebase initialization failed - {e}")


# Firebase initialization
def init_firestore():
    try:
        # Checking if admin exists, if not create default
        admin_ref = db.collection('admin').document('default_admin')
        if not admin_ref.get().exists:
            hashed_password = generate_password_hash('taikhamyang2025')
            admin_ref.set({
                'username': 'khamyang',
                'password': hashed_password
            })
            print("Default admin created")
    except Exception as e:
        print(f"Error initializing Firestore: {e}")


#======= Set up logging======
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_api_call(func):
    """Decorator to log API calls"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            logger.info(f"API call: {func.__name__} - IP: {request.remote_addr}")
            result = func(*args, **kwargs)
            logger.info(f"API call successful: {func.__name__}")
            return result
        except Exception as e:
            logger.error(f"API call failed: {func.__name__} - Error: {str(e)}")
            raise
    return wrapper


# ==============Simple in-memory rate limiting (use Redis in production)=============
rate_limit_store = defaultdict(list)


def rate_limit(max_requests=5, window_minutes=1):
    """Rate limiting decorator"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            window_start = current_time - (window_minutes * 60)

            # Clean old requests
            rate_limit_store[client_ip] = [
                req_time for req_time in rate_limit_store[client_ip]
                if req_time > window_start
            ]

            # Check rate limit
            if len(rate_limit_store[client_ip]) >= max_requests:
                logger.warning(f"Rate limit exceeded for IP: {client_ip}")
                return jsonify({
                    'success': False,
                    'message': f'Too many requests. Try again in {window_minutes} minutes.'
                }), 429

            # Add current request
            rate_limit_store[client_ip].append(current_time)

            return func(*args, **kwargs)

        return wrapper

    return decorator


#============date time===========
def get_current_time():
    """Get current time - timezone naive for consistency with Firestore"""
    return datetime.now()


def make_expire_time(hours=1):
    """Create expiration time that's compatible with current_time"""
    return datetime.now() + timedelta(hours=hours)


def are_datetimes_compatible(dt1, dt2):
    """Check if two datetime objects can be compared safely"""
    dt1_aware = hasattr(dt1, 'tzinfo') and dt1.tzinfo is not None
    dt2_aware = hasattr(dt2, 'tzinfo') and dt2.tzinfo is not None
    return dt1_aware == dt2_aware


def normalize_datetime_for_comparison(dt1, dt2):
    """Normalize two datetime objects for safe comparison"""
    dt1_aware = hasattr(dt1, 'tzinfo') and dt1.tzinfo is not None
    dt2_aware = hasattr(dt2, 'tzinfo') and dt2.tzinfo is not None

    if dt1_aware and not dt2_aware:
        # Make dt2 timezone-aware
        dt2 = dt2.replace(tzinfo=timezone.utc)
    elif not dt1_aware and dt2_aware:
        # Make dt1 timezone-aware
        dt1 = dt1.replace(tzinfo=timezone.utc)
    elif dt1_aware and dt2_aware:
        # Both are timezone-aware, ensure they're in the same timezone
        if dt1.tzinfo != dt2.tzinfo:
            dt1 = dt1.astimezone(timezone.utc)
            dt2 = dt2.astimezone(timezone.utc)

    return dt1, dt2


def is_expired(expires_at, current_time=None):
    """Check if a datetime has expired, handling timezone issues"""
    if current_time is None:
        current_time = datetime.now()

    current_time, expires_at = normalize_datetime_for_comparison(current_time, expires_at)
    return current_time > expires_at
#====UTILITY FUNCTION=====
def generate_reset_token():
    """Generate a secure reset token"""
    return secrets.token_urlsafe(32)


def generate_otp():
    """Generate a 6-digit OTP"""
    return secrets.randbelow(900000) + 100000


def hash_token(token):
    """Hash a token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()


def send_email_via_brevo(to_email, subject, html_content):
    """Send email using Brevo API"""
    if not BREVO_API_KEY:
        print("Error: BREVO_API_KEY not configured")
        return False

    url = "https://api.brevo.com/v3/smtp/email"
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    data = {
        "sender": {
            "name": "Tai-Khamyang Dictionary",
            "email": "noreply@taikhamyang.com"  # Make sure this email is verified in Brevo
        },
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }

    try:
        response = requests.post(url, json=data, headers=headers)
        print(f"Brevo API Response: {response.status_code} - {response.text}")

        if response.status_code == 201:
            print(f"Email sent successfully to {to_email}")
            return True
        else:
            print(f"Email sending failed: {response.text}")
            return False
    except Exception as e:
        print(f"Email sending exception: {e}")
        return False


def send_sms_otp(phone_number, otp):
    """Send SMS OTP using Twilio"""
    if not twilio_client:
        print("Error: Twilio not configured")
        return False

    # Ensure phone number format is correct
    if not phone_number.startswith('+'):
        if phone_number.startswith('91'):
            phone_number = '+' + phone_number
        elif len(phone_number) == 10:
            phone_number = '+91' + phone_number
        else:
            phone_number = '+' + phone_number

    message = f"Your Tai-Khamyang verification code is: {otp}. This code will expire in 10 minutes. Do not share this code with anyone."

    try:
        message_instance = twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"SMS sent successfully. SID: {message_instance.sid}")
        return True
    except Exception as e:
        print(f"SMS sending failed: {e}")
        return False


def send_whatsapp_otp(phone_number, otp):
    """Send WhatsApp OTP using Twilio"""
    if not twilio_client:
        print("Error: Twilio not configured")
        return False

    # Format phone number for WhatsApp
    if not phone_number.startswith('whatsapp:'):
        # Ensure proper format
        if not phone_number.startswith('+'):
            if phone_number.startswith('91'):
                phone_number = '+' + phone_number
            elif len(phone_number) == 10:
                phone_number = '+91' + phone_number
            else:
                phone_number = '+' + phone_number

        phone_number = f"whatsapp:{phone_number}"

    message = f"🔐 *Tai-Khamyang Dictionary*\n\nYour verification code is: *{otp}*\n\n⏰ This code will expire in 10 minutes.\n🔒 Do not share this code with anyone.\n\nThank you for using Tai-Khamyang Dictionary!"

    try:
        message_instance = twilio_client.messages.create(
            body=message,
            from_=TWILIO_WHATSAPP_NUMBER,
            to=phone_number
        )
        print(f"WhatsApp message sent successfully. SID: {message_instance.sid}")
        return True
    except Exception as e:
        print(f"WhatsApp sending failed: {e}")
        return False


def normalize_phone_number(phone):
    """Normalize phone number to multiple possible formats"""
    if not phone:
        return None

    # Remove all non-digit characters except +
    cleaned = ''.join(c for c in phone if c.isdigit() or c == '+')

    # Remove any extra + signs (keep only the first one)
    if cleaned.count('+') > 1:
        plus_index = cleaned.find('+')
        cleaned = cleaned[plus_index:plus_index + 1] + cleaned[plus_index + 1:].replace('+', '')

    # Add country code if not present (assuming India +91)
    if not cleaned.startswith('+'):
        if cleaned.startswith('91') and len(cleaned) > 10:
            # Already has country code without +
            cleaned = '+' + cleaned
        elif len(cleaned) == 10:
            # 10 digit Indian number
            cleaned = '+91' + cleaned
        elif cleaned.startswith('0') and len(cleaned) == 11:
            # Remove leading 0 and add country code
            cleaned = '+91' + cleaned[1:]
        else:
            # Add + to whatever format it is
            cleaned = '+' + cleaned

    return cleaned


#  Add a function to standardize phone numbers in  database
def standardize_phone_format():
    """One-time function to standardize all phone numbers in database"""
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        updated_users = 0
        updated_sellers = 0

        # Update users collection
        users_ref = db.collection('users')
        for doc in users_ref.stream():
            user_data = doc.to_dict()
            old_phone = user_data.get('phone')
            if old_phone:
                new_phone = normalize_phone_number(old_phone)
                if new_phone != old_phone:
                    doc.reference.update({'phone': new_phone})
                    print(f"Updated user {doc.id}: {old_phone} -> {new_phone}")
                    updated_users += 1

        # Update sellers collection
        sellers_ref = db.collection('sellers')
        for doc in sellers_ref.stream():
            seller_data = doc.to_dict()
            old_phone = seller_data.get('phone')
            if old_phone:
                new_phone = normalize_phone_number(old_phone)
                if new_phone != old_phone:
                    doc.reference.update({'phone': new_phone})
                    print(f"Updated seller {doc.id}: {old_phone} -> {new_phone}")
                    updated_sellers += 1

        return jsonify({
            'success': True,
            'updated_users': updated_users,
            'updated_sellers': updated_sellers
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Also add this helper function to validate phone numbers
def is_valid_indian_phone(phone):
    """Validate if phone number is a valid Indian phone number"""
    if not phone:
        return False

    normalized = normalize_phone_number(phone)

    # Check if it's a valid Indian phone number
    if normalized.startswith('+91'):
        # Should be exactly 13 characters (+91 + 10 digits)
        if len(normalized) != 13:
            return False

        # Check if the number after +91 is valid (starts with 6, 7, 8, or 9)
        mobile_number = normalized[3:]  # Remove +91
        if len(mobile_number) == 10 and mobile_number[0] in '6789':
            return True

    return False


# validate email format
def is_valid_email(email):
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
# Routes
@app.route('/')
def home():
    if 'user_id' in session:  # Check if user is logged in
        return render_template('index.html')  # Showing main index for logged-in users
    else:
        return render_template('indexx.html')  # Showing landing page for non-logged-in users


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('home'))  # redirect to indexx.html
    return render_template('index.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out')
    return redirect(url_for('home'))  # back to indexx.html

#Register backed for indexx.html
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # register route, add:
        if not is_valid_indian_phone(phone):
            flash('Please enter a valid Indian phone number')
            return redirect(url_for('register'))

        # Validation
        if not all([name, phone, email, address, password, confirm_password]):
            flash('Please fill all fields')
            return redirect(url_for('register'))

        if '@' not in email or '.' not in email.split('@')[1]:
            flash('Please enter a valid email address')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            # Checking if phone number already exists in database
            users_ref = db.collection('users')
            existing_user = users_ref.where('phone', '==', phone).limit(1).stream()
            existing_email = users_ref.where('email', '==', email).limit(1).stream()
            if len(list(existing_user)) > 0:
                flash('Your phone number is already registered')
                return redirect(url_for('register'))

            if len(list(existing_email)) > 0:
                flash('This email address is already registered')
                return redirect(url_for('register'))

            # Register new users
            user_ref = users_ref.add({
                'name': name,
                'phone': phone,
                'email': email,
                'address': address,
                'password': hashed_password,
                'registered_at': firestore.SERVER_TIMESTAMP
            })

            # Auto login after registration redirect to index.html
            session['user_logged_in'] = True
            session['user_name'] = name
            session['user_id'] = user_ref[1].id
            session['user_email'] = email
            flash('Registration successful! Welcome to Tai-Khamyang App')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('Registration failed. Please try again.')
            print(f"Registration error: {e}")
            return redirect(url_for('register'))

    return render_template('register.html')

#Login backed for indexx.html
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form.get('phone')
        password = request.form.get('password')

        try:
            users_ref = db.collection('users')
            user_docs = users_ref.where('phone', '==', phone).limit(1).stream()
            user_doc = None

            for doc in user_docs:
                user_doc = doc
                break

            if user_doc and check_password_hash(user_doc.to_dict()['password'], password):
                session['user_id'] = user_doc.id
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials. Please try again🥲.')
                return redirect(url_for('login'))
        except Exception as e:
            flash('Login failed. Please try again🥲.')
            print(f"Login error: {e}")
            return redirect(url_for('login'))

    return render_template('login.html')

#====sorry=========
@app.route('/sorry')
def sorry_page():
    return render_template('sorry.html')


#==================Route to dictionary section=====================
@app.route('/dictionary')
def dictionary():
    return render_template('dictionary.html')
#---------------API Routes------------

@app.route('/api/words')
def get_words():
    search = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'tai_khamyang')

    try:
        words_ref = db.collection('words')
        words = []

        for doc in words_ref.stream():
            word_data = doc.to_dict()
            word_data['id'] = doc.id

            # Handle both old audio_path (local) and new audio_url (Firebase) for backward compatibility
            if word_data.get('audio_url'):
                word_data['has_audio'] = True
                word_data['audio_file_url'] = word_data.get('signed_audio_url') or word_data.get('audio_url')
            elif word_data.get('audio_path'):
                # Keep backward compatibility with old local files
                word_data['has_audio'] = True
                word_data['audio_file_url'] = f"/static/audio/{word_data['audio_path']}"
            else:
                word_data['has_audio'] = False
                word_data['audio_file_url'] = None

            # Client-side search filtering
            if search:
                search_lower = search.lower()
                if (search_lower in word_data.get('tai_khamyang', '').lower() or
                        search_lower in word_data.get('english', '').lower() or
                        search_lower in word_data.get('assamese', '').lower()):
                    words.append(word_data)
            else:
                words.append(word_data)

        # Client-side sorting
        if sort_by in ['tai_khamyang', 'english', 'assamese']:
            words.sort(key=lambda x: x.get(sort_by, '').lower())

        return jsonify(words)
    except Exception as e:
        print(f"Error getting words: {e}")
        return jsonify([])


# Add this new route to stream dictionary audio (similar to songs)
@app.route('/api/words/<word_id>/audio')
def stream_word_audio(word_id):
    try:
        word_ref = db.collection('words').document(word_id)
        word = word_ref.get()

        if not word.exists:
            return "Word not found", 404

        word_data = word.to_dict()
        audio_url = word_data.get('signed_audio_url') or word_data.get('audio_url')

        if not audio_url:
            return "No audio file available", 404

        # Proxy the audio file
        import requests
        response = requests.get(audio_url, stream=True)

        def generate():
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    yield chunk

        content_type = word_data.get('audio_content_type', 'audio/mpeg')

        return app.response_class(
            generate(),
            mimetype=content_type,
            headers={
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=3600',
                'Access-Control-Allow-Origin': '*'
            }
        )

    except Exception as e:
        print(f"Stream word audio error: {e}")
        return f"Streaming error: {str(e)}", 500

#==============Route to song section============
@app.route('/songs')
def songs():
    return render_template('songs.html')

#---------------API Routes------------
@app.route('/api/songs')
def get_songs():
    search = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'title')

    try:
        songs_ref = db.collection('songs')
        songs = []

        for doc in songs_ref.stream():
            song_data = doc.to_dict()
            song_data['id'] = doc.id

            # Ensure we have a working URL
            if 'signed_url' in song_data and song_data['signed_url']:
                # Prefer signed URL as it's more reliable
                song_data['file_url'] = song_data['signed_url']

            # Add debug info
            song_data['has_audio'] = bool(song_data.get('file_url'))
            song_data['content_type'] = song_data.get('content_type', 'audio/mpeg')

            # Client-side search filtering
            if search:
                search_lower = search.lower()
                if (search_lower in song_data.get('title', '').lower() or
                        search_lower in song_data.get('description', '').lower()):
                    songs.append(song_data)
            else:
                songs.append(song_data)

        # Client-side sorting
        if sort_by in ['title', 'description']:
            songs.sort(key=lambda x: x.get(sort_by, '').lower())

        return jsonify(songs)
    except Exception as e:
        print(f"Error getting songs: {e}")
        return jsonify([])

@app.route('/api/songs/<song_id>/stream')
def stream_audio(song_id):
    try:
        song_ref = db.collection('songs').document(song_id)
        song = song_ref.get()

        if not song.exists:
            return "Song not found", 404

        song_data = song.to_dict()
        file_url = song_data.get('signed_url') or song_data.get('file_url')

        if not file_url:
            return "No audio file available", 404

        # Proxy the audio file
        import requests
        response = requests.get(file_url, stream=True)

        def generate():
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    yield chunk

        content_type = song_data.get('content_type', 'audio/mpeg')

        return app.response_class(
            generate(),
            mimetype=content_type,
            headers={
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'public, max-age=3600',
                'Access-Control-Allow-Origin': '*'
            }
        )

    except Exception as e:
        print(f"Stream audio error: {e}")
        return f"Streaming error: {str(e)}", 500


@app.route('/api/songs', methods=['POST'])
def add_song():
    if 'admin_logged_in' not in session or not session['admin_logged_in']:
        print("[ERROR] Unauthorized access attempt")
        return jsonify({'error': 'Unauthorized - Please login as admin'}), 401

    try:
        print("[DEBUG] Request headers:", request.headers)
        print("[DEBUG] Request content type:", request.content_type)

        if 'multipart/form-data' not in request.content_type:
            return jsonify({'error': 'Content-Type must be multipart/form-data'}), 400

        title = request.form.get('title')
        description = request.form.get('description', '')
        audio_file = request.files.get('audio')

        print("[DEBUG] Received title:", title)
        print("[DEBUG] Received description:", description)
        print("[DEBUG] Audio file received:", bool(audio_file))

        if not title:
            return jsonify({'error': 'Song title is required'}), 400

        if not audio_file or audio_file.filename == '':
            return jsonify({'error': 'Audio file is required'}), 400

        # Enhanced file validation
        allowed_extensions = {'mp3', 'wav', 'ogg', 'm4a', 'aac'}
        file_ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''

        if file_ext not in allowed_extensions:
            return jsonify({
                'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'
            }), 400

        # Generate unique filename
        filename = secure_filename(audio_file.filename)
        unique_filename = f"songs/{uuid.uuid4()}_{filename}"
        print("[DEBUG] Generated storage path:", unique_filename)

        # Upload to Firebase Storage with proper settings
        try:
            blob = bucket.blob(unique_filename)

            # Set proper content type based on file extension
            content_type_mapping = {
                'mp3': 'audio/mpeg',
                'wav': 'audio/wav',
                'ogg': 'audio/ogg',
                'm4a': 'audio/mp4',
                'aac': 'audio/aac'
            }
            content_type = content_type_mapping.get(file_ext, 'audio/mpeg')

            # Upload with proper metadata
            blob.upload_from_file(
                audio_file,
                content_type=content_type
            )

            # Make public and set proper cache control
            blob.make_public()

            # Set CORS-friendly metadata
            blob.metadata = {
                'firebaseStorageDownloadTokens': str(uuid.uuid4())
            }
            blob.patch()

            # Generate proper download URL
            file_url = blob.public_url

            # Alternative: Generate signed URL for better compatibility
            from datetime import timedelta
            signed_url = blob.generate_signed_url(
                expiration=datetime.now() + timedelta(days=365),
                method='GET'
            )

            print("[SUCCESS] File uploaded to:", file_url)
            print("[SUCCESS] Signed URL:", signed_url)

        except Exception as upload_error:
            print("[ERROR] Firebase upload failed:", str(upload_error))
            return jsonify({
                'error': f'File upload failed: {str(upload_error)}'
            }), 500

        # Save to Firestore with both URLs
        song_data = {
            'title': title,
            'description': description,
            'file_url': file_url,
            'signed_url': signed_url,  # Backup URL
            'content_type': content_type,
            'file_extension': file_ext,
            'created_at': firestore.SERVER_TIMESTAMP,
            'file_path': unique_filename
        }

        try:
            doc_ref = db.collection('songs').document()
            doc_ref.set(song_data)
            print("[SUCCESS] Song saved with ID:", doc_ref.id)

            return jsonify({
                'success': True,
                'id': doc_ref.id,
                'file_url': file_url,
                'signed_url': signed_url
            })

        except Exception as firestore_error:
            print("[ERROR] Firestore save failed:", str(firestore_error))
            try:
                blob.delete()
                print("[CLEANUP] Deleted orphaned audio file")
            except Exception as delete_error:
                print("[ERROR] Failed to cleanup orphaned file:", str(delete_error))

            return jsonify({
                'error': f'Database save failed: {str(firestore_error)}'
            }), 500

    except Exception as e:
        print("[CRITICAL] Unexpected error:", str(e))
        return jsonify({
            'error': f'Unexpected server error: {str(e)}'
        }), 500

@app.route('/api/songs/<song_id>/test-audio')
def test_audio_url(song_id):
    try:
        song_ref = db.collection('songs').document(song_id)
        song = song_ref.get()

        if not song.exists:
            return jsonify({'error': 'Song not found'}), 404

        song_data = song.to_dict()
        file_url = song_data.get('file_url')
        signed_url = song_data.get('signed_url')

        if not file_url:
            return jsonify({'error': 'No audio URL found'}), 404

        # Try to access the URL
        import requests
        try:
            response = requests.head(file_url, timeout=10)
            url_accessible = response.status_code == 200
            content_type = response.headers.get('content-type', 'unknown')
            content_length = response.headers.get('content-length', 'unknown')
        except Exception as e:
            url_accessible = False
            content_type = 'error'
            content_length = str(e)

        return jsonify({
            'song_id': song_id,
            'file_url': file_url,
            'signed_url': signed_url,
            'url_accessible': url_accessible,
            'content_type': content_type,
            'content_length': content_length,
            'test_timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/songs/<song_id>', methods=['PUT'])
def update_song(song_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        title = request.form.get('title')
        description = request.form.get('description')
        audio_file = request.files.get('audio')

        # Get existing song data
        song_ref = db.collection('songs').document(song_id)
        song = song_ref.get()
        if not song.exists:
            return jsonify({'error': 'Song not found'}), 404

        song_data = song.to_dict()
        file_url = song_data.get('file_url')

        # Handle file upload if present
        if audio_file:
            # Delete old file if exists
            if file_url:
                try:
                    old_blob_name = file_url.split('/')[-1]
                    old_blob = bucket.blob(old_blob_name)
                    old_blob.delete()
                except Exception as e:
                    print(f"Warning: Could not delete old audio file - {e}")

            # Upload new file
            filename = secure_filename(audio_file.filename)
            unique_filename = f"songs/{uuid.uuid4()}_{filename}"

            blob = bucket.blob(unique_filename)
            blob.upload_from_file(
                audio_file,
                content_type=audio_file.content_type
            )
            blob.make_public()
            file_url = blob.public_url

        # Prepare update data
        update_data = {
            'title': title,
            'description': description,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        if file_url:
            update_data['file_url'] = file_url

        song_ref.update(update_data)

        return jsonify({
            'success': True,
            'file_url': file_url
        })

    except Exception as e:
        print(f'Error in update_song: {e}')
        return jsonify({'error': str(e)}), 500


@app.route('/api/songs/<song_id>', methods=['DELETE'])
def delete_song(song_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        song_ref = db.collection('songs').document(song_id)
        song = song_ref.get()

        if not song.exists:
            return jsonify({'error': 'Song not found'}), 404

        song_data = song.to_dict()

        # Delete the audio file from storage if it exists
        if 'file_url' in song_data:
            try:
                # Extract the blob path from the URL
                file_url = song_data['file_url']
                # This assumes your URL looks like: https://storage.googleapis.com/bucket-name/path/to/file
                blob_name = file_url.split('storage.googleapis.com/')[1].split('/')[1:]
                blob_name = '/'.join(blob_name)
                blob = bucket.blob(blob_name)
                blob.delete()
            except Exception as e:
                print(f"Warning: Could not delete audio file - {e}")

        song_ref.delete()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============= SHOP ROUTES =============
@app.route('/shopnow')
def shop():
    return render_template('shop.html')

#seller register
@app.route('/api/seller/register', methods=['POST'])
def seller_register():
    try:
        data = request.get_json()

        # Check if a seller with this email already exists
        sellers_ref = db.collection('sellers')
        existing_sellers = list(sellers_ref.where('email', '==', data['email']).stream())

        if existing_sellers:
            return jsonify({'success': False, 'message': 'Seller with this email already exists'})

        # Create the new seller document using data from the form
        seller_data = {
            'id': str(uuid.uuid4()),
            'full_name': data['fullName'],  # From the "Full Name" field
            'business_name': data['shopName'],  # From the "Shop Name" field
            'email': data['email'],
            'password': generate_password_hash(data['password']),  # Securely hash the password
            'phone': data['phone'],
            'whatsapp': data['whatsapp'],
            'created_at': datetime.now(),
            'status': 'active'
        }

        # Added the new seller data to the 'sellers' collection in Firestore
        db.collection('sellers').document(seller_data['id']).set(seller_data)

        return jsonify({'success': True, 'message': 'Seller registered successfully'})

    except Exception as e:
        # Return an error if something goes wrong
        print(f"Seller registration error: {e}")
        return jsonify({'success': False, 'message': str(e)})

#seller login
@app.route('/api/seller/login', methods=['POST'])
def seller_login():
    try:
        data = request.get_json()

        # Find the seller in the database by their email address
        sellers_ref = db.collection('sellers')
        sellers = list(sellers_ref.where('email', '==', data['email']).stream())

        # If no seller is found with that email, return an error
        if not sellers:
            return jsonify({'success': False, 'message': 'Invalid email or password'})

        seller_doc = sellers[0]
        seller = seller_doc.to_dict()
        seller['id'] = seller_doc.id  # Get the document ID

        # Check if the provided password matches the stored hashed password
        if check_password_hash(seller['password'], data['password']):
            # If login is successful, store seller info in the session
            session['seller_id'] = seller['id']
            session['seller_name'] = seller['business_name']

            # Return success and seller details to the frontend
            return jsonify({'success': True, 'seller': {
                'id': seller['id'],
                'business_name': seller['business_name'],
                'email': seller['email']
            }})
        else:
            # If passwords do not match, return an error
            return jsonify({'success': False, 'message': 'Invalid email or password'})

    except Exception as e:
        print(f"Seller login error: {e}")
        return jsonify({'success': False, 'message': str(e)})


#seller logout
@app.route('/api/seller/logout', methods=['POST'])
def seller_logout():
    session.pop('seller_id', None)
    session.pop('seller_name', None)
    return jsonify({'success': True})

#product add button
@app.route('/api/products/add', methods=['POST'])
def add_product():
    try:
        if 'seller_id' not in session:
            return jsonify({'success': False, 'message': 'Please login first'})

        data = request.get_json()

        product_data = {
            'id': str(uuid.uuid4()),
            'seller_id': session['seller_id'],
            'name': data['name'],
            'description': data['description'],
            'category': data['category'],
            'price': float(data['price']),
            'original_price': float(data.get('originalPrice', data['price'])),
            'sizes': data.get('sizes', []),
            'images': data.get('images', []),
            'stock_quantity': int(data.get('stockQuantity', 0)),
            'status': 'active',
            'created_at': datetime.now(),
            'updated_at': datetime.now()
        }

        # Add to Firestore
        db.collection('products').document(product_data['id']).set(product_data)

        return jsonify({'success': True, 'message': 'Product added successfully'})

    except Exception as e:
        print(f"Add product error: {e}")
        return jsonify({'success': False, 'message': str(e)})

# -------------- UTILITY ROUTES -------------
@app.route('/api/upload-image', methods=['POST'])
def upload_image():
    try:
        if 'image' not in request.files:
            return jsonify({'success': False, 'message': 'No image file provided'})

        file = request.files['image']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})

        # Validate file type
        allowed_extensions = {'jpg', 'jpeg', 'png', 'webp'}
        if not ('.' in file.filename and
                file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
            return jsonify({'success': False, 'message': 'Invalid file type'})

        # Validate file size (2MB max)
        file.seek(0, 2)  # Seek to end of file
        file_size = file.tell()
        file.seek(0)  # Reset to beginning

        if file_size > 2 * 1024 * 1024:  # 2MB
            return jsonify({'success': False, 'message': 'File too large. Maximum size is 2MB'})

        # Generate unique filename
        filename = secure_filename(file.filename)
        unique_filename = f"products/{uuid.uuid4()}_{filename}"

        # Upload to Firebase Storage
        blob = bucket.blob(unique_filename)
        blob.upload_from_file(
            file,
            content_type=file.content_type
        )
        blob.make_public()

        return jsonify({
            'success': True,
            'imageUrl': blob.public_url
        })

    except Exception as e:
        print(f"Image upload error: {e}")
        return jsonify({'success': False, 'message': str(e)})

#Get products details
@app.route('/api/products', methods=['GET'])
def get_products():
    try:
        products_ref = db.collection('products')
        products = list(products_ref.where('status', '==', 'active').stream())

        product_list = []
        for product_doc in products:
            product_data = product_doc.to_dict()
            product_data['id'] = product_doc.id

            # Get seller info
            try:
                seller_doc = db.collection('sellers').document(product_data['seller_id']).get()
                if seller_doc.exists:
                    seller_data = seller_doc.to_dict()
                    product_data['seller_info'] = {
                        'business_name': seller_data.get('business_name', 'Unknown Seller'),
                        'whatsapp': seller_data.get('whatsapp', ''),
                        'phone': seller_data.get('phone', '')
                    }
                else:
                    product_data['seller_info'] = {
                        'business_name': 'Unknown Seller',
                        'whatsapp': '',
                        'phone': ''
                    }
            except Exception as seller_error:
                print(f"Error getting seller info: {seller_error}")
                product_data['seller_info'] = {
                    'business_name': 'Unknown Seller',
                    'whatsapp': '',
                    'phone': ''
                }

            product_list.append(product_data)

        return jsonify({'success': True, 'products': product_list})

    except Exception as e:
        print(f"Get products error: {e}")
        return jsonify({'success': False, 'message': str(e)})

#Manage product
@app.route('/api/seller/products', methods=['GET'])
def get_seller_products():
    try:
        if 'seller_id' not in session:
            return jsonify({'success': False, 'message': 'Please login first'})

        products_ref = db.collection('products')
        products = list(products_ref.where('seller_id', '==', session['seller_id']).stream())

        product_list = []
        for product_doc in products:
            product_data = product_doc.to_dict()
            product_data['id'] = product_doc.id
            product_list.append(product_data)

        return jsonify({'success': True, 'products': product_list})

    except Exception as e:
        print(f"Get seller products error: {e}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/products/<product_id>', methods=['DELETE'])
def delete_product(product_id):
    try:
        # Check if a seller is logged in
        if 'seller_id' not in session:
            return jsonify({'success': False, 'message': 'Authentication required. Please login first.'}), 401

        # Get the product from the database
        product_ref = db.collection('products').document(product_id)
        product_doc = product_ref.get()

        if not product_doc.exists:
            return jsonify({'success': False, 'message': 'Product not found.'}), 404

        product_data = product_doc.to_dict()

        # IMPORTANT: Check if the product's seller_id matches the logged-in seller's ID
        if product_data['seller_id'] != session['seller_id']:
            return jsonify({'success': False, 'message': 'Unauthorized. You can only delete your own products.'}), 403

        # If all checks pass, delete the product
        product_ref.delete()

        return jsonify({'success': True, 'message': 'Product deleted successfully'})

    except Exception as e:
        print(f"Delete product error: {e}")
        return jsonify({'success': False, 'message': 'A server error occurred.'}), 500

# ----------------- PRODUCT ROUTES -------------

@app.route('/api/products/<product_id>', methods=['GET'])
def get_product_details(product_id):
    try:
        product_doc = db.collection('products').document(product_id).get()
        if not product_doc.exists:
            return jsonify({'success': False, 'message': 'Product not found'})

        product_data = product_doc.to_dict()
        product_data['id'] = product_doc.id

        # Get seller info
        seller_doc = db.collection('sellers').document(product_data['seller_id']).get()
        if seller_doc.exists:
            seller_data = seller_doc.to_dict()
            product_data['seller_info'] = {
                'business_name': seller_data['business_name'],
                'whatsapp': seller_data['whatsapp'],
                'phone': seller_data['phone']
            }

        return jsonify({'success': True, 'product': product_data})

    except Exception as e:
        print(f"Get product details error: {e}")
        return jsonify({'success': False, 'message': str(e)})


@app.route('/api/products/<product_id>', methods=['PUT'])
def update_product(product_id):
    try:
        if 'seller_id' not in session:
            return jsonify({'success': False, 'message': 'Please login first'})

        # Check if product belongs to seller
        product_doc = db.collection('products').document(product_id).get()
        if not product_doc.exists:
            return jsonify({'success': False, 'message': 'Product not found'})

        product_data = product_doc.to_dict()
        if product_data['seller_id'] != session['seller_id']:
            return jsonify({'success': False, 'message': 'Unauthorized'})

        data = request.get_json()

        # Update product data
        update_data = {
            'name': data['name'],
            'description': data['description'],
            'category': data['category'],
            'price': float(data['price']),
            'original_price': float(data.get('originalPrice', data['price'])),
            'stock_quantity': int(data.get('stockQuantity', 0)),
            'updated_at': datetime.now()
        }

        # Update in Firestore
        db.collection('products').document(product_id).update(update_data)

        return jsonify({'success': True, 'message': 'Product updated successfully'})

    except Exception as e:
        print(f"Update product error: {e}")
        return jsonify({'success': False, 'message': str(e)})

#=============about page============
@app.route('/about')
def about():
    return render_template('about.html')

#===============admin page route================
@app.route('/admin')
def admin():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))
    return render_template('admin.html')

#admin page login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            admin_ref = db.collection('admin').document('default_admin')
            admin_doc = admin_ref.get()

            if admin_doc.exists:
                admin_data = admin_doc.to_dict()
                if admin_data['username'] == username and check_password_hash(admin_data['password'], password):
                    session['admin_logged_in'] = True
                    return redirect(url_for('admin'))
                else:
                    flash('Invalid credentials')
            else:
                flash('Admin not found')
        except Exception as e:
            flash('Login failed. Please try again.')
            print(f"Admin login error: {e}")

    return render_template('admin_login.html')

#admin page logout button
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('home'))

#------------words-----------
@app.route('/api/words', methods=['POST'])
def add_word():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        tai_khamyang = request.form.get('tai_khamyang')
        english = request.form.get('english')
        assamese = request.form.get('assamese')

        audio_file = request.files.get('audio')
        audio_url = None
        signed_url = None

        if audio_file and audio_file.filename:
            # Validate file type
            allowed_extensions = {'mp3', 'wav', 'ogg', 'm4a', 'aac'}
            file_ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''

            if file_ext not in allowed_extensions:
                return jsonify({
                    'error': f'Invalid audio file type. Allowed: {", ".join(allowed_extensions)}'
                }), 400

            # Generate unique filename for Firebase Storage
            filename = secure_filename(audio_file.filename)
            unique_filename = f"dictionary_audio/{uuid.uuid4()}_{filename}"

            try:
                # Upload to Firebase Storage
                blob = bucket.blob(unique_filename)

                # Set proper content type based on file extension
                content_type_mapping = {
                    'mp3': 'audio/mpeg',
                    'wav': 'audio/wav',
                    'ogg': 'audio/ogg',
                    'm4a': 'audio/mp4',
                    'aac': 'audio/aac'
                }
                content_type = content_type_mapping.get(file_ext, 'audio/mpeg')

                # Upload with proper metadata
                blob.upload_from_file(
                    audio_file,
                    content_type=content_type
                )

                # Make public and set proper cache control
                blob.make_public()

                # Set CORS-friendly metadata
                blob.metadata = {
                    'firebaseStorageDownloadTokens': str(uuid.uuid4())
                }
                blob.patch()

                # Generate public URL
                audio_url = blob.public_url

                # Generate signed URL for better compatibility
                from datetime import timedelta
                signed_url = blob.generate_signed_url(
                    expiration=datetime.now() + timedelta(days=365),
                    method='GET'
                )

                print(f"[SUCCESS] Dictionary audio uploaded: {audio_url}")

            except Exception as upload_error:
                print(f"[ERROR] Firebase upload failed: {str(upload_error)}")
                return jsonify({
                    'error': f'Audio file upload failed: {str(upload_error)}'
                }), 500

        # Prepare word data
        word_data = {
            'tai_khamyang': tai_khamyang,
            'english': english,
            'assamese': assamese,
            'created_at': firestore.SERVER_TIMESTAMP
        }

        # Add audio URLs if file was uploaded
        if audio_url:
            word_data.update({
                'audio_url': audio_url,
                'signed_audio_url': signed_url,
                'audio_content_type': content_type,
                'audio_file_path': unique_filename
            })

        # Save to Firestore
        words_ref = db.collection('words')
        doc_ref = words_ref.add(word_data)

        return jsonify({
            'success': True,
            'id': doc_ref[1].id,
            'audio_url': audio_url,
            'signed_audio_url': signed_url
        })

    except Exception as e:
        print(f"Error adding word: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/words/<word_id>', methods=['PUT'])
def update_word(word_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        # Handle both JSON and form data
        if request.is_json:
            data = request.get_json()
            tai_khamyang = data.get('tai_khamyang')
            english = data.get('english')
            assamese = data.get('assamese')
            audio_url = None
            signed_url = None
        else:
            tai_khamyang = request.form.get('tai_khamyang')
            english = request.form.get('english')
            assamese = request.form.get('assamese')

            # Handle file upload if present
            audio_file = request.files.get('audio')
            audio_url = None
            signed_url = None

            if audio_file and audio_file.filename:
                # Get existing word data to delete old audio file
                word_ref = db.collection('words').document(word_id)
                existing_word = word_ref.get()

                if existing_word.exists:
                    existing_data = existing_word.to_dict()
                    old_file_path = existing_data.get('audio_file_path')

                    # Delete old audio file if it exists
                    if old_file_path:
                        try:
                            old_blob = bucket.blob(old_file_path)
                            old_blob.delete()
                            print(f"[SUCCESS] Deleted old audio file: {old_file_path}")
                        except Exception as delete_error:
                            print(f"[WARNING] Could not delete old audio file: {delete_error}")

                # Validate new file type
                allowed_extensions = {'mp3', 'wav', 'ogg', 'm4a', 'aac'}
                file_ext = audio_file.filename.rsplit('.', 1)[1].lower() if '.' in audio_file.filename else ''

                if file_ext not in allowed_extensions:
                    return jsonify({
                        'error': f'Invalid audio file type. Allowed: {", ".join(allowed_extensions)}'
                    }), 400

                # Upload new file
                filename = secure_filename(audio_file.filename)
                unique_filename = f"dictionary_audio/{uuid.uuid4()}_{filename}"

                try:
                    blob = bucket.blob(unique_filename)

                    # Set proper content type
                    content_type_mapping = {
                        'mp3': 'audio/mpeg',
                        'wav': 'audio/wav',
                        'ogg': 'audio/ogg',
                        'm4a': 'audio/mp4',
                        'aac': 'audio/aac'
                    }
                    content_type = content_type_mapping.get(file_ext, 'audio/mpeg')

                    blob.upload_from_file(
                        audio_file,
                        content_type=content_type
                    )
                    blob.make_public()

                    # Set metadata
                    blob.metadata = {
                        'firebaseStorageDownloadTokens': str(uuid.uuid4())
                    }
                    blob.patch()

                    audio_url = blob.public_url

                    # Generate signed URL
                    from datetime import timedelta
                    signed_url = blob.generate_signed_url(
                        expiration=datetime.now() + timedelta(days=365),
                        method='GET'
                    )

                    print(f"[SUCCESS] New dictionary audio uploaded: {audio_url}")

                except Exception as upload_error:
                    print(f"[ERROR] Firebase upload failed: {str(upload_error)}")
                    return jsonify({
                        'error': f'Audio file upload failed: {str(upload_error)}'
                    }), 500

        # Validate required fields
        if not all([tai_khamyang, english, assamese]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Prepare update data
        word_data = {
            'tai_khamyang': tai_khamyang,
            'english': english,
            'assamese': assamese,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        # Add audio URLs if new file was uploaded
        if audio_url:
            word_data.update({
                'audio_url': audio_url,
                'signed_audio_url': signed_url,
                'audio_content_type': content_type,
                'audio_file_path': unique_filename
            })

        # Update in Firestore
        word_ref = db.collection('words').document(word_id)
        word_ref.update(word_data)

        return jsonify({
            'message': 'Word updated successfully',
            'audio_url': audio_url,
            'signed_audio_url': signed_url
        })

    except Exception as e:
        print(f'Error in update_word: {e}')
        return jsonify({'error': str(e)}), 500

@app.route('/api/words/<word_id>', methods=['DELETE'])
def delete_word(word_id):
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        word_ref = db.collection('words').document(word_id)
        word = word_ref.get()

        if not word.exists:
            return jsonify({'error': 'Word not found'}), 404

        word_data = word.to_dict()

        # Delete the audio file from Firebase Storage if it exists
        if 'audio_file_path' in word_data:
            try:
                blob = bucket.blob(word_data['audio_file_path'])
                blob.delete()
                print(f"[SUCCESS] Deleted audio file: {word_data['audio_file_path']}")
            except Exception as e:
                print(f"[WARNING] Could not delete audio file: {e}")

        # Delete the word document
        word_ref.delete()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============== USER PASSWORD RESET ============
@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forgot_password.html')

# =============== PASSWORD RESET API ENDPOINTS ============

@app.route('/api/auth/forgot-password/email', methods=['POST'])
@rate_limit(max_requests=3, window_minutes=15)
@log_api_call
def forgot_password_email():
    """Handle email-based password reset"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})

        # Check if user exists with this email
        users_ref = db.collection('users')
        user_docs = list(users_ref.where('email', '==', email).limit(1).stream())

        seller_docs = []
        if not user_docs:
            sellers_ref = db.collection('sellers')
            seller_docs = list(sellers_ref.where('email', '==', email).limit(1).stream())

        if not user_docs and not seller_docs:
            return jsonify({'success': True, 'message': 'If this email exists, a reset link has been sent'})

        # Determine user type and get user data
        if user_docs:
            user_doc = user_docs[0]
            user_data = user_doc.to_dict()
            user_id = user_doc.id
            user_type = 'user'
            user_name = user_data.get('name', 'User')
        else:
            user_doc = seller_docs[0]
            user_data = user_doc.to_dict()
            user_id = user_doc.id
            user_type = 'seller'
            user_name = user_data.get('full_name', user_data.get('business_name', 'User'))

        # Generate reset token
        reset_token = generate_reset_token()
        token_hash = hash_token(reset_token)
        expires_at = make_expire_time(hours=1)  # Use utility function

        # Store reset token in database
        reset_data = {
            'user_id': user_id,
            'user_type': user_type,
            'email': email,
            'token_hash': token_hash,
            'expires_at': expires_at,
            'used': False,
            'created_at': get_current_time()  # Use utility function
        }

        db.collection('password_resets').document().set(reset_data)

        # Generate reset URL
        reset_url = f"{request.host_url}reset-password?token={reset_token}"

        # Create email content (keeping the same HTML as before)
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Password</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 28px;">Reset Your Password</h1>
            </div>

            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <p style="font-size: 16px; margin-bottom: 20px;">Hello {user_name},</p>

                <p style="font-size: 16px; margin-bottom: 20px;">
                    We received a request to reset your password for your Tai-Khamyang account. 
                    If you didn't make this request, you can safely ignore this email.
                </p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" 
                       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                              color: white; 
                              padding: 15px 30px; 
                              text-decoration: none; 
                              border-radius: 8px; 
                              font-weight: bold; 
                              display: inline-block;
                              font-size: 16px;">
                        Reset My Password
                    </a>
                </div>

                <p style="font-size: 14px; color: #666; margin-top: 30px;">
                    This link will expire in 1 hour for security reasons.
                </p>

                <p style="font-size: 14px; color: #666;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{reset_url}" style="color: #667eea; word-break: break-all;">{reset_url}</a>
                </p>

                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

                <p style="font-size: 12px; color: #999; text-align: center;">
                    This email was sent from Tai-Khamyang Dictionary Platform<br>
                    If you have any questions, please contact our support team.
                </p>
            </div>
        </body>
        </html>
        """

        # Send email
        if send_email_via_brevo(email, "Reset Your Tai-Khamyang Password", html_content):
            return jsonify({'success': True, 'message': 'Reset link sent to your email'})
        else:
            return jsonify({'success': False, 'message': 'Failed to send email. Please try again.'})

    except Exception as e:
        print(f"Email reset error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})


@app.route('/api/auth/forgot-password/phone', methods=['POST'])
@rate_limit(max_requests=5, window_minutes=15)  # Max 5 SMS/WhatsApp requests per 15 minutes
@log_api_call
def forgot_password_phone():
    """Handle phone-based password reset"""
    try:
        data = request.get_json()
        phone = data.get('phone')
        method = data.get('method', 'sms')  # 'sms' or 'whatsapp'

        if not phone:
            return jsonify({'success': False, 'message': 'Phone number is required'})

        # Normalize phone number (remove spaces, etc.)
        phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')

        # Add country code if not present (assuming India +91)
        if not phone.startswith('+'):
            if phone.startswith('91'):
                phone = '+' + phone
            elif len(phone) == 10:
                phone = '+91' + phone
            else:
                phone = '+' + phone

        # Check if user exists with this phone
        users_ref = db.collection('users')
        user_docs = list(users_ref.where('phone', '==', phone).limit(1).stream())

        seller_docs = []
        if not user_docs:
            # Check in sellers collection
            sellers_ref = db.collection('sellers')
            seller_docs = list(sellers_ref.where('phone', '==', phone).limit(1).stream())

        if not user_docs and not seller_docs:
            # Don't reveal if phone exists or not for security
            return jsonify({'success': True, 'message': 'If this phone number is registered, a code has been sent'})

        # Determine user type and get user data
        if user_docs:
            user_doc = user_docs[0]
            user_data = user_doc.to_dict()
            user_id = user_doc.id
            user_type = 'user'
        else:
            user_doc = seller_docs[0]
            user_data = user_doc.to_dict()
            user_id = user_doc.id
            user_type = 'seller'

        # Generate OTP
        otp = generate_otp()
        expires_at = datetime.now() + timedelta(minutes=10)  # OTP expires in 10 minutes

        # Store OTP in database
        otp_data = {
            'user_id': user_id,
            'user_type': user_type,
            'phone': phone,
            'otp': str(otp),
            'method': method,
            'expires_at': expires_at,
            'used': False,
            'created_at': datetime.now()
        }

        # Delete any existing OTP for this phone
        existing_otps = db.collection('phone_otps').where('phone', '==', phone).where('used', '==', False)
        for doc in existing_otps.stream():
            doc.reference.delete()

        # Store new OTP
        db.collection('phone_otps').document().set(otp_data)

        # Send OTP based on method
        success = False
        if method == 'whatsapp':
            success = send_whatsapp_otp(phone, otp)
        else:  # SMS
            success = send_sms_otp(phone, otp)

        if success:
            return jsonify({'success': True, 'message': f'Verification code sent via {method.upper()}'})
        else:
            return jsonify({'success': False, 'message': f'Failed to send {method.upper()} message. Please try again.'})

    except Exception as e:
        print(f"Phone reset error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})


@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP and generate reset token"""
    try:
        data = request.get_json()
        phone = data.get('phone')
        otp = data.get('otp')
        method = data.get('method', 'sms')

        if not phone or not otp:
            return jsonify({'success': False, 'message': 'Phone and OTP are required'})

        # Normalize phone number
        phone = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        if not phone.startswith('+'):
            if phone.startswith('91'):
                phone = '+' + phone
            elif len(phone) == 10:
                phone = '+91' + phone
            else:
                phone = '+' + phone

        # Find matching OTP
        otp_ref = db.collection('phone_otps')
        otp_docs = list(otp_ref.where('phone', '==', phone)
                        .where('otp', '==', str(otp))
                        .where('used', '==', False)
                        .limit(1).stream())

        if not otp_docs:
            return jsonify({'success': False, 'message': 'Invalid or expired verification code'})

        otp_doc = otp_docs[0]
        otp_data = otp_doc.to_dict()

        # Check if OTP has expired
        if datetime.now() > otp_data['expires_at']:
            return jsonify({'success': False, 'message': 'Verification code has expired'})

        # Mark OTP as used
        otp_doc.reference.update({'used': True})

        # Generate reset token
        reset_token = generate_reset_token()
        token_hash = hash_token(reset_token)
        expires_at = datetime.now() + timedelta(hours=1)  # Token expires in 1 hour

        # Store reset token
        reset_data = {
            'user_id': otp_data['user_id'],
            'user_type': otp_data['user_type'],
            'phone': phone,
            'token_hash': token_hash,
            'expires_at': expires_at,
            'used': False,
            'created_at': datetime.now()
        }

        db.collection('password_resets').document().set(reset_data)

        return jsonify({
            'success': True,
            'message': 'Verification successful',
            'token': reset_token
        })

    except Exception as e:
        print(f"OTP verification error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

# Clean up expired tokens (you can call this periodically)
@app.route('/api/auth/cleanup-tokens', methods=['POST'])
def cleanup_expired_tokens():
    """Clean up expired reset tokens and OTPs"""
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        now = datetime.now()

        # Clean up expired password reset tokens
        reset_tokens = db.collection('password_resets').where('expires_at', '<', now)
        deleted_resets = 0
        for doc in reset_tokens.stream():
            doc.reference.delete()
            deleted_resets += 1

        # Clean up expired OTPs
        expired_otps = db.collection('phone_otps').where('expires_at', '<', now)
        deleted_otps = 0
        for doc in expired_otps.stream():
            doc.reference.delete()
            deleted_otps += 1

        return jsonify({
            'success': True,
            'deleted_resets': deleted_resets,
            'deleted_otps': deleted_otps
        })

    except Exception as e:
        print(f"Cleanup error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/reset-password')
def reset_password_page():
    token = request.args.get('token')
    if not token:
        flash('Invalid or missing reset token')
        return redirect(url_for('login'))
    return render_template('reset_password.html')


# Add input validation
def validate_input(data, required_fields):
    """Validate input data"""
    errors = []

    for field in required_fields:
        if field not in data or not data[field] or not data[field].strip():
            errors.append(f"{field} is required")

    if 'email' in data and data['email']:
        if not is_valid_email(data['email']):
            errors.append("Invalid email format")

    if 'phone' in data and data['phone']:
        if not isValidPhone(data['phone']):
            errors.append("Invalid phone number format")

    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            errors.append("Password must be at least 8 characters long")
        if not any(c.isupper() for c in data['password']):
            errors.append("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in data['password']):
            errors.append("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in data['password']):
            errors.append("Password must contain at least one number")
        if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in data['password']):
            errors.append("Password must contain at least one special character")

    return errors


def isValidPhone(phone):
    """Validate phone number format"""
    if not phone:
        return False

    # Remove all non-digit characters except +
    cleaned = ''.join(c for c in phone if c.isdigit() or c == '+')

    # Check if it's a valid Indian phone number
    if cleaned.startswith('+91'):
        return len(cleaned) == 13  # +91 + 10 digits
    elif cleaned.startswith('91'):
        return len(cleaned) == 12  # 91 + 10 digits
    elif len(cleaned) == 10:
        return True  # 10 digit number

    return False


# Add database connection retry logic
def retry_db_operation(func, max_retries=3):
    """Retry database operations"""
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            logger.warning(f"DB operation failed (attempt {attempt + 1}): {str(e)}")
            if attempt == max_retries - 1:
                raise
            time.sleep(1)  # Wait 1 second before retry


# Add health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.collection('users').limit(1).get()

        # Test email service
        email_status = "configured" if BREVO_API_KEY else "not configured"

        # Test SMS service
        sms_status = "configured" if twilio_client else "not configured"

        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'email_service': email_status,
            'sms_service': sms_status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

#=======================SYSTEM VERIIFICATION FOR PASSWORD CHANGE=========================

@app.route('/api/auth/verify-account', methods=['POST'])
@log_api_call
def verify_account():
    try:
        print("VERIFY ACCOUNT ENDPOINT HIT!")
        data = request.get_json()
        if not data:
            print("No data received")
            return jsonify({'success': False, 'message': 'No data provided'}), 400

        print(f"Received data: {data}")
        email = data.get('email')
        phone = data.get('phone')

        if not email or not phone:
            return jsonify({'success': False, 'message': 'Both email and phone are required'}), 400

        # Normalize phone number and create multiple formats to check
        normalized_phone = normalize_phone_number(phone)

        # Create different phone formats to check against database
        phone_formats = []
        phone_formats.append(phone)  # Original input
        phone_formats.append(normalized_phone)  # Normalized format (+91xxxxxxxxxx)

        # Without country code (xxxxxxxxxx)
        if normalized_phone.startswith('+91'):
            phone_formats.append(normalized_phone[3:])  # Remove +91
        elif normalized_phone.startswith('91'):
            phone_formats.append(normalized_phone[2:])  # Remove 91

        # With 91 prefix (91xxxxxxxxxx)
        if normalized_phone.startswith('+91'):
            phone_formats.append(normalized_phone[1:])  # Remove +, keep 91
        elif len(normalized_phone) == 10:
            phone_formats.append('91' + normalized_phone)

        # Remove duplicates
        phone_formats = list(set(phone_formats))

        print(f"Checking phone formats: {phone_formats}")
        logger.info(f"Verification attempt for email: {email}, phone formats: {phone_formats}")

        found_user = None
        user_type = None

        # Check in users collection first
        users_ref = db.collection('users')
        email_query = users_ref.where('email', '==', email).stream()
        for doc in email_query:
            user_data = doc.to_dict()
            user_phone = user_data.get('phone', '')
            print(f"Found user with email {email}, phone in DB: '{user_phone}'")

            # Check if any phone format matches
            if user_phone in phone_formats:
                print(f"Phone match found in users! DB phone: '{user_phone}' matches one of: {phone_formats}")
                found_user = doc
                user_type = 'user'
                break

        # Check in sellers collection if not found in users
        if not found_user:
            sellers_ref = db.collection('sellers')
            email_query = sellers_ref.where('email', '==', email).stream()
            for doc in email_query:
                seller_data = doc.to_dict()
                seller_phone = seller_data.get('phone', '')
                print(f"Found seller with email {email}, phone in DB: '{seller_phone}'")

                # Check if any phone format matches
                if seller_phone in phone_formats:
                    print(f"Phone match found in sellers! DB phone: '{seller_phone}' matches one of: {phone_formats}")
                    found_user = doc
                    user_type = 'seller'
                    break

        logger.info(f"Found user: {found_user is not None}, type: {user_type}")

        if not found_user:
            print(f"DEBUG: No matches found for email: {email}, phone formats: {phone_formats}")
            return jsonify({'success': False, 'message': 'No account found with matching email and phone number'}), 404

        # Generate reset token
        reset_token = generate_reset_token()
        token_hash = hash_token(reset_token)
        expires_at = make_expire_time(hours=1)  # Use utility function

        # Store reset token
        reset_data = {
            'user_id': found_user.id,
            'user_type': user_type,
            'email': email,
            'phone': phone,
            'token_hash': token_hash,
            'expires_at': expires_at,
            'used': False,
            'created_at': get_current_time()  # Use utility function
        }

        db.collection('password_resets').document().set(reset_data)
        logger.info(f"Reset token generated for {user_type} {found_user.id}")

        return jsonify({
            'success': True,
            'message': 'Account verified successfully',
            'token': reset_token,
            'user_type': user_type
        })

    except Exception as e:
        logger.error(f"Account verification error: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred during verification'}), 500



# Add a test endpoint to verify token functionality (remove in production)
@app.route('/api/auth/test-token/<token>', methods=['GET'])
def test_token(token):
    """Test endpoint to check token validity - REMOVE IN PRODUCTION"""
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        hashed_token = hash_token(token)

        reset_ref = db.collection('password_resets')
        reset_docs = []

        for doc in reset_ref.where('token_hash', '==', hashed_token).stream():
            reset_data = doc.to_dict()
            reset_docs.append({
                'id': doc.id,
                'user_id': reset_data.get('user_id'),
                'user_type': reset_data.get('user_type'),
                'email': reset_data.get('email'),
                'phone': reset_data.get('phone'),
                'used': reset_data.get('used'),
                'expires_at': reset_data.get('expires_at'),
                'created_at': reset_data.get('created_at')
            })

        return jsonify({
            'token': token,
            'hashed_token': hashed_token,
            'found_tokens': reset_docs,
            'current_time': datetime.now().isoformat()
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/auth/reset-password', methods=['POST'])
@log_api_call
def reset_password_submit():
    """Handle password reset via token"""
    try:
        data = request.get_json()
        token = data.get('token')
        new_password = data.get('newPassword')

        print(f"[DEBUG] Reset password attempt with token: {token[:10]}...")  # Log first 10 chars only

        if not token or not new_password:
            return jsonify({'success': False, 'message': 'Missing token or password'})

        # Validate password strength
        password_errors = validate_password_strength(new_password)
        if password_errors:
            return jsonify({'success': False, 'message': '; '.join(password_errors)})

        # Hash token to compare with stored hash
        hashed_token = hash_token(token)
        print(f"[DEBUG] Looking for token hash: {hashed_token[:10]}...")

        # Find matching token entry from Firestore
        reset_ref = db.collection('password_resets')
        reset_docs = []

        # Query for matching token hash
        for doc in reset_ref.where('token_hash', '==', hashed_token).where('used', '==', False).stream():
            reset_docs.append(doc)

        print(f"[DEBUG] Found {len(reset_docs)} matching reset tokens")

        if not reset_docs:
            return jsonify({'success': False, 'message': 'Invalid or expired reset token'})

        reset_doc = reset_docs[0]
        reset_data = reset_doc.to_dict()

        print(f"[DEBUG] Reset token data: user_id={reset_data.get('user_id')}, user_type={reset_data.get('user_type')}")

        # Fix timezone awareness issue
        expires_at = reset_data['expires_at']
        current_time = datetime.now()

        # Handle both timezone-aware and timezone-naive datetime objects
        if hasattr(expires_at, 'tzinfo') and expires_at.tzinfo is not None:
            # expires_at is timezone-aware, make current_time timezone-aware too
            from datetime import timezone
            if current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=timezone.utc)
        else:
            # expires_at is timezone-naive, ensure current_time is also timezone-naive
            if hasattr(current_time, 'tzinfo') and current_time.tzinfo is not None:
                current_time = current_time.replace(tzinfo=None)

        # Check if token has expired
        if current_time > expires_at:
            print("[DEBUG] Token has expired")
            return jsonify({'success': False, 'message': 'Reset token has expired'})

        # Get user details
        user_id = reset_data['user_id']
        user_type = reset_data['user_type']

        # Determine which collection to use
        if user_type == 'seller':
            user_collection = db.collection('sellers')
        else:
            user_collection = db.collection('users')

        user_ref = user_collection.document(user_id)

        # Check if user still exists
        user_doc = user_ref.get()
        if not user_doc.exists:
            print(f"[DEBUG] User not found: {user_id} in {user_type} collection")
            return jsonify({'success': False, 'message': 'User account not found'})

        user_data = user_doc.to_dict()
        print(f"[DEBUG] Found user: {user_data.get('email', 'No email')} in {user_type} collection")

        # Hash the new password
        hashed_password = generate_password_hash(new_password)
        print("[DEBUG] New password hashed successfully")

        # Update user's password
        update_data = {
            'password': hashed_password,
            'password_updated_at': datetime.now(),
            'updated_at': datetime.now()
        }

        user_ref.update(update_data)
        print(f"[DEBUG] Password updated for user {user_id}")

        # Mark the token as used
        reset_doc.reference.update({
            'used': True,
            'used_at': datetime.now()
        })
        print("[DEBUG] Reset token marked as used")

        # Clean up old reset tokens for this user (optional)
        try:
            old_tokens = db.collection('password_resets').where('user_id', '==', user_id).where('used', '==', False)
            deleted_count = 0
            for doc in old_tokens.stream():
                if doc.id != reset_doc.reference.id:
                    doc.reference.delete()
                    deleted_count += 1
            print(f"[DEBUG] Cleaned up {deleted_count} old tokens")
        except Exception as cleanup_error:
            print(f"[WARNING] Token cleanup failed: {cleanup_error}")

        return jsonify({
            'success': True,
            'message': 'Password has been reset successfully',
            'user_type': user_type
        })

    except Exception as e:
        print(f"[ERROR] Reset password error: {e}")
        logger.error(f"Reset password error: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred while resetting password'})


def validate_password_strength(password):
    """Validate password strength and return list of errors"""
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long")

    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")

    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")

    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")

    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        errors.append("Password must contain at least one special character")

    return errors

# Add this function to your app.py for debugging
@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    """Debug endpoint to check users in database - REMOVE IN PRODUCTION"""
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        users_data = []

        # Get users from users collection
        users_ref = db.collection('users')
        for doc in users_ref.limit(10).stream():
            user_data = doc.to_dict()
            users_data.append({
                'id': doc.id,
                'email': user_data.get('email', 'N/A'),
                'phone': user_data.get('phone', 'N/A'),
                'name': user_data.get('name', 'N/A'),
                'type': 'user'
            })

        # Get users from sellers collection
        sellers_ref = db.collection('sellers')
        for doc in sellers_ref.limit(10).stream():
            seller_data = doc.to_dict()
            users_data.append({
                'id': doc.id,
                'email': seller_data.get('email', 'N/A'),
                'phone': seller_data.get('phone', 'N/A'),
                'name': seller_data.get('full_name', seller_data.get('business_name', 'N/A')),
                'type': 'seller'
            })

        return jsonify({
            'success': True,
            'users': users_data,
            'total_found': len(users_data)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


# Add this function to test a specific user
@app.route('/api/debug/find-user', methods=['POST'])
def debug_find_user():
    """Debug endpoint to find a specific user - REMOVE IN PRODUCTION"""
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        data = request.get_json()
        email = data.get('email')
        phone = data.get('phone')

        if phone:
            phone = normalize_phone_number(phone)

        results = []

        # Search in users collection
        users_ref = db.collection('users')

        if email:
            for doc in users_ref.where('email', '==', email).stream():
                user_data = doc.to_dict()
                results.append({
                    'id': doc.id,
                    'collection': 'users',
                    'email': user_data.get('email'),
                    'phone': user_data.get('phone'),
                    'email_match': user_data.get('email') == email,
                    'phone_match': user_data.get('phone') == phone if phone else 'N/A'
                })

        if phone:
            for doc in users_ref.where('phone', '==', phone).stream():
                user_data = doc.to_dict()
                # Avoid duplicates
                if not any(r['id'] == doc.id for r in results):
                    results.append({
                        'id': doc.id,
                        'collection': 'users',
                        'email': user_data.get('email'),
                        'phone': user_data.get('phone'),
                        'email_match': user_data.get('email') == email if email else 'N/A',
                        'phone_match': user_data.get('phone') == phone
                    })

        # Search in sellers collection
        sellers_ref = db.collection('sellers')

        if email:
            for doc in sellers_ref.where('email', '==', email).stream():
                seller_data = doc.to_dict()
                results.append({
                    'id': doc.id,
                    'collection': 'sellers',
                    'email': seller_data.get('email'),
                    'phone': seller_data.get('phone'),
                    'email_match': seller_data.get('email') == email,
                    'phone_match': seller_data.get('phone') == phone if phone else 'N/A'
                })

        if phone:
            for doc in sellers_ref.where('phone', '==', phone).stream():
                seller_data = doc.to_dict()
                # Avoid duplicates
                if not any(r['id'] == doc.id for r in results):
                    results.append({
                        'id': doc.id,
                        'collection': 'sellers',
                        'email': seller_data.get('email'),
                        'phone': seller_data.get('phone'),
                        'email_match': seller_data.get('email') == email if email else 'N/A',
                        'phone_match': seller_data.get('phone') == phone
                    })

        return jsonify({
            'success': True,
            'search_email': email,
            'search_phone': phone,
            'results': results,
            'total_found': len(results)
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ====================== route to handle seller password reset requests====================

@app.route('/api/auth/seller/forgot-password', methods=['POST'])
@rate_limit(max_requests=3, window_minutes=15)
@log_api_call
def seller_forgot_password():
    """Handle seller password reset requests"""
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            return jsonify({'success': False, 'message': 'Email is required'})

        # Check if seller exists with this email
        sellers_ref = db.collection('sellers')
        seller_docs = list(sellers_ref.where('email', '==', email).limit(1).stream())

        if not seller_docs:
            # Don't reveal if email exists or not for security
            return jsonify({'success': True, 'message': 'If this email exists, a reset link has been sent'})

        seller_doc = seller_docs[0]
        seller_data = seller_doc.to_dict()

        # Generate reset token
        reset_token = generate_reset_token()
        token_hash = hash_token(reset_token)
        expires_at = make_expire_time(hours=1)

        # Store reset token in database
        reset_data = {
            'user_id': seller_doc.id,
            'user_type': 'seller',
            'email': email,
            'token_hash': token_hash,
            'expires_at': expires_at,
            'used': False,
            'created_at': get_current_time()
        }

        db.collection('password_resets').document().set(reset_data)

        # Generate reset URL
        reset_url = f"{request.host_url}reset-password?token={reset_token}"

        # Create email content
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Reset Your Seller Password</title>
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
            <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: white; margin: 0; font-size: 28px;">Reset Your Seller Password</h1>
            </div>

            <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <p style="font-size: 16px; margin-bottom: 20px;">Hello {seller_data.get('business_name', 'Seller')},</p>

                <p style="font-size: 16px; margin-bottom: 20px;">
                    We received a request to reset your password for your Tai-Khamyang seller account. 
                    If you didn't make this request, you can safely ignore this email.
                </p>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" 
                       style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                              color: white; 
                              padding: 15px 30px; 
                              text-decoration: none; 
                              border-radius: 8px; 
                              font-weight: bold; 
                              display: inline-block;
                              font-size: 16px;">
                        Reset My Password
                    </a>
                </div>

                <p style="font-size: 14px; color: #666; margin-top: 30px;">
                    This link will expire in 1 hour for security reasons.
                </p>

                <p style="font-size: 14px; color: #666;">
                    If the button doesn't work, copy and paste this link into your browser:<br>
                    <a href="{reset_url}" style="color: #667eea; word-break: break-all;">{reset_url}</a>
                </p>

                <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">

                <p style="font-size: 12px; color: #999; text-align: center;">
                    This email was sent from Tai-Khamyang Seller Platform<br>
                    If you have any questions, please contact our support team.
                </p>
            </div>
        </body>
        </html>
        """

        # Send email
        if send_email_via_brevo(email, "Reset Your Tai-Khamyang Seller Password", html_content):
            return jsonify({'success': True, 'message': 'Reset link sent to your email'})
        else:
            return jsonify({'success': False, 'message': 'Failed to send email. Please try again.'})

    except Exception as e:
        print(f"Seller email reset error: {e}")
        return jsonify({'success': False, 'message': 'An error occurred. Please try again.'})

if __name__ == '__main__':
    print("Starting initialization...")  # debug print
    init_firestore()
    print("Initialization complete, starting server...")  # debug print
    app.run(debug=True, host='0.0.0.0', port=5000)