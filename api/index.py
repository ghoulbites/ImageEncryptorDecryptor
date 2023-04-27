from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, World! This is some random change'

@app.route('/about')
def about():
    return 'About'