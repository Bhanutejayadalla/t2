from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
import jwt
from functools import wraps
import datetime
from flask import send_from_directory
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Configuration
app.config['MYSQL_HOST']     = 'localhost'
app.config['MYSQL_USER']     = 'root'
app.config['MYSQL_PASSWORD'] = '2008'
app.config['MYSQL_DB']       = 'studentdb'
app.config['SECRET_KEY']     = 'your_jwt_secret'

mysql = MySQL(app)

# Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or not token.startswith('Bearer '):
            return jsonify({'error': 'Token missing'}), 401
        token = token.split()[1]
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data['student_id']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        return f(user_id, *args, **kwargs)
    return decorated


@app.route('/')
def serve_frontend():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(current_dir, 'index.html')
# Register route
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    pw_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "INSERT INTO students (first_name, last_name, email, date_of_birth, password_hash) "
            "VALUES (%s, %s, %s, %s, %s)",
            (data['first_name'], data['last_name'], data['email'], data['date_of_birth'], pw_hash)
        )
        mysql.connection.commit()
    except:
        return jsonify({'error': 'Email already registered'}), 400
    return jsonify({'message': 'Registration successful'})

# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    cur = mysql.connection.cursor()
    cur.execute("SELECT student_id, password_hash FROM students WHERE email = %s", (data['email'],))
    row = cur.fetchone()
    if not row or not bcrypt.check_password_hash(row[1], data['password']):
        return jsonify({'error': 'Invalid credentials'}), 400
    token = jwt.encode({
        'student_id': row[0],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})

@app.route('/health')
def home():
    return 'Student Login API is running!'
# Protected route
@app.route('/api/registered', methods=['GET'])
@token_required
def registered(user_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT first_name, last_name, email FROM students WHERE student_id = %s", (user_id,))
    user = cur.fetchone()
    return jsonify({'user': {
        'first_name': user[0],
        'last_name':  user[1],
        'email':      user[2]
    }})

if __name__ == '__main__':
    app.run(debug=True)
