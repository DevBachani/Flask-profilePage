from flask import Flask, request, jsonify, session
from flask_mongoengine import MongoEngine
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import uuid
from mongoengine import Document, StringField, EmailField

app = Flask(__name__)

# Configuration
app.config['MONGODB_SETTINGS'] = {
    'db': 'dbmongocrud',
    'host': 'localhost',
    'port': 27017
}
app.secret_key = 'your_secret_key'  # Secret key for session management

db = MongoEngine()
db.init_app(app)

# User Model
class User(db.Document):
    username = db.StringField(required=True)
    name = db.StringField(required=True)
    email = db.StringField(required=True, unique=True)
    parent_email = db.StringField()
    phone_number = db.StringField()
    college_school = db.StringField()
    standard = db.StringField()
    password = db.StringField(required=True)

    def to_json(self):
        return {
            "id": str(self.id),
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "parent_email": self.parent_email,
            "phone_number": self.phone_number,
            "college_school": self.college_school,
            "standard": self.standard
        }

# Root Endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({
        "status": "Login API is online"
    }), 200




app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MongoDB User model
class User(Document):
    username = StringField(required=True, unique=True)
    name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    parent_email = EmailField()
    phone_number = StringField()
    college_school = StringField()
    standard = StringField()
    password = StringField(required=True)

# Register User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    name = data.get('name')
    email = data.get('email')
    parent_email = data.get('parent_email')
    phone_number = data.get('phone_number')
    college_school = data.get('college_school')
    standard = data.get('standard')
    password = data.get('password')

    if not username or not name or not email or not password:
        return jsonify({'error': 'Username, name, email, and password are required'}), 400

    if User.objects(email=email).first() or User.objects(username=username).first():
        return jsonify({'error': 'Username or Email already exists'}), 400

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Create new user
    new_user = User(username=username, name=name, email=email, parent_email=parent_email,
                    phone_number=phone_number, college_school=college_school, standard=standard, password=hashed_password.decode('utf-8'))
    new_user.save()

    return jsonify({'message': 'User registered successfully', 'user': new_user.to_json()}), 201

# Login User
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Find the user by email
    user = User.objects(email=email).first()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Generate session ID
    session_id = str(uuid.uuid4())
    session['session_id'] = session_id
    session['user_id'] = str(user.id)

    return jsonify({
        'message': 'Login successful',
        'user': user.to_json(),
        'session_id': session_id
    }), 200

if __name__ == '__main__':
    app.run(debug=True)


# Get User Profile
@app.route('/profile', methods=['GET'])
def get_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.objects(id=session['user_id']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_json()), 200

# Update User Profile
@app.route('/profile/update', methods=['PUT'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.objects(id=session['user_id']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    user.update(**data)
    return jsonify({'message': 'Profile updated successfully'}), 200

# Change Password
@app.route('/profile/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user = User.objects(id=session['user_id']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not check_password_hash(user.password, old_password):
        return jsonify({'error': 'Incorrect old password'}), 400
    
    user.update(password=generate_password_hash(new_password))
    return jsonify({'message': 'Password changed successfully'}), 200

# Logout
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

if __name__ == "__main__":
    app.run(debug=True)
