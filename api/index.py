from flask import Flask, request, send_file
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from io import BytesIO
from PIL import Image

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, World! This is some random change'

@app.route('/about')
def about():
    return 'About'
