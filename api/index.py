from flask import Flask, request, send_file, jsonify
from Crypto.Random import get_random_bytes
from werkzeug.utils import secure_filename
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from io import BytesIO


app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, World! This is some random change'

@app.route('/about')
def about():
    return 'About'

@app.route('/aes-encrypt', methods=['POST'])
def aesEncrypt():
    # Check if file is in the request
    if 'image' not in request.files:
        return 'No file found', 400

    # Check if key is in the request
    if 'key' not in request.form:
        return 'No key found', 400

    # Get the file and key from the request
    file = request.files['image']
    key = request.form['key']

    # Determine the file format from the filename
    filename = secure_filename(file.filename)
    file_extension = filename.rsplit('.', 1)[1].lower()

    # Check if file format is supported
    if file_extension not in ['jpg', 'jpeg', 'png']:
        return 'Unsupported file format', 400

    # Read the file contents
    file_contents = file.read()

    # Generate a 256-bit key from the input key
    key_bytes = key.encode('utf-8')
    key_256 = key_bytes[:32] + b'\0' * (32 - len(key_bytes))

    # Encrypt the file
    cipher = AES.new(key_256, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(file_contents, AES.block_size))

    # Return the encrypted file in the same format as the input file
    output_file = BytesIO()
    output_file.write(cipher.iv)
    output_file.write(ct_bytes)

    # if file_extension == 'jpg' or file_extension == 'jpeg':
    #     return output_file.getvalue(), {'Content-Type': 'image/jpeg'}
    # elif file_extension == 'png':
    #     return output_file.getvalue(), {'Content-Type': 'image/png'}
    
    if file_extension == 'jpg' or file_extension == 'jpeg':
        return file.read(), {'Content-Type': 'image/jpeg'}
    elif file_extension == 'png':
        return file.read(), {'Content-Type': 'image/png'}