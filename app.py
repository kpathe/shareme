from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re  # Import regular expression module

app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Chat model
class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)

# Function to format the message content, making links clickable
def format_message(content):
    url_pattern = r'(https?://\S+)'  # Regex pattern to match URLs
    return re.sub(url_pattern, r'<a href="\1" target="_blank">\1</a>', content)

# Index route
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return render_template('index.html', user_email=user.email)
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('chat'))
        flash("Invalid email or password", "error")
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Account created successfully", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

# Chat route
@app.route('/chat')
def chat():
    if 'user_id' not in session:
        flash("Please log in to access the chat.", "error")
        return redirect(url_for('login'))
    
    # Retrieve the logged-in user
    user = User.query.get(session['user_id'])
    # Retrieve all previous messages to display in the chat
    messages = Chat.query.order_by(Chat.timestamp).all()

    return render_template('chat.html', messages=messages, format_message=format_message, user_email=user.email)

# SocketIO event
@socketio.on('message')
def handle_message(data):
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            timestamp = datetime.now().strftime('%H:%M:%S')  # Time for the frontend
            date = datetime.now().strftime('%Y-%m-%d')      # Date for the frontend
            
            # Save the message in the database
            new_chat = Chat(sender=user.email, content=data)
            db.session.add(new_chat)
            db.session.commit()
            
            # Broadcast the message
            emit('message', {
                'sender': user.email,
                'content': data,
                'time': timestamp,
                'date': date
            }, broadcast=True)

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove the user session
    return redirect(url_for('index'))  # Redirect to the index page

# Run the app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure the database tables are created before starting the app
    socketio.run(app, debug=True)
