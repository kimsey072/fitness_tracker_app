
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3, os, hashlib

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def init_db():
    with sqlite3.connect("database.db") as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            exercise TEXT,
            duration INTEGER,
            calories INTEGER
        )''')
        conn.execute('''CREATE TABLE IF NOT EXISTS calories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            food TEXT,
            amount INTEGER
        )''')
init_db()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        try:
            with sqlite3.connect("database.db") as conn:
                conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            return redirect(url_for('login'))
        except:
            return "Username already exists."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hash_password(request.form['password'])
        with sqlite3.connect("database.db") as conn:
            user = conn.execute('SELECT id FROM users WHERE username=? AND password=?', (username, password)).fetchone()
            if user:
                session['user_id'] = user[0]
                return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/log_workout', methods=['GET', 'POST'])
def log_workout():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        with sqlite3.connect("database.db") as conn:
            conn.execute('INSERT INTO workouts (user_id, date, exercise, duration, calories) VALUES (?, ?, ?, ?, ?)',
                (session['user_id'], request.form['date'], request.form['exercise'], request.form['duration'], request.form['calories']))
        return redirect(url_for('history'))
    return render_template('log_workout.html')

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect("database.db") as conn:
        data = conn.execute('SELECT date, exercise, duration, calories FROM workouts WHERE user_id=?', (session['user_id'],)).fetchall()
    return render_template('history.html', workouts=data)

@app.route('/bmi', methods=['GET', 'POST'])
def bmi():
    bmi_value = None
    if request.method == 'POST':
        weight = float(request.form['weight'])
        height = float(request.form['height']) / 100
        bmi_value = round(weight / (height ** 2), 2)
    return render_template('bmi.html', bmi=bmi_value)

@app.route('/calories', methods=['GET', 'POST'])
def calorie_tracker():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        with sqlite3.connect("database.db") as conn:
            conn.execute('INSERT INTO calories (user_id, date, food, amount) VALUES (?, ?, ?, ?)',
                (session['user_id'], request.form['date'], request.form['food'], request.form['amount']))
    with sqlite3.connect("database.db") as conn:
        entries = conn.execute('SELECT date, food, amount FROM calories WHERE user_id=?', (session['user_id'],)).fetchall()
    return render_template('calories.html', entries=entries)

if __name__ == '__main__':
    app.run(debug=True)
