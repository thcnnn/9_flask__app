from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import json

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for session management

# Path to the JSON file where users will be stored
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as file:
        json.dump(users, file, indent=4)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form
        if 'login' not in data or 'password' not in data:
            return jsonify({"error": "Login and password are required"}), 400

        login = data['login']
        password = data['password']

        users_db = load_users()

        if login in users_db:
            return jsonify({"error": "User already exists"}), 400

        hashed_password = generate_password_hash(password)
        users_db[login] = {
            "login": login,
            "password_hash": hashed_password,
            "registration_date": datetime.now().isoformat()
        }

        save_users(users_db)
        return jsonify({"message": "User registered successfully"}), 201

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        if 'login' not in data or 'password' not in data:
            return jsonify({"error": "Login and password are required"}), 400

        login = data['login']
        password = data['password']

        users_db = load_users()
        user = users_db.get(login)

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({"error": "Invalid login or password"}), 401

        session['user'] = login
        return redirect(url_for('get_user', login=login))

    return render_template('login.html')

@app.route('/user/<login>/', methods=['GET'])
def get_user(login):
    users_db = load_users()
    user = users_db.get(login)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_data = user.copy()
    del user_data['password_hash']  # Do not expose password hash

    return jsonify(user_data), 200

if __name__ == '__main__':
    app.run(ssl_context=('ssl/server.crt', 'ssl/server.key'), debug=True)
