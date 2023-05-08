from flask import Flask, request, send_file, jsonify
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from io import BytesIO
from PIL import Image

app = Flask(__name__)

@app.route('/')
def home():
    return 'Hello, World! This is some random change'

@app.route('/about')
def about():
    return 'About'

@app.route('/aes-encrypt', methods=['POST'])
def aesEncrypt():
    # Get key and file from request
    key = request.form['key']
    file = request.files['file'].read()

    # Hash key to get a 256-bit key
    hashed_key = SHA256(key.encode()).digest()

    # Encrypt the file using AES-GCM
    nonce = get_random_bytes(12)
    cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=nonce)
    cipherText, tag = cipher.encrypt_and_digest(pad(file, AES.block_size))

    # Convert the encrypted file and tag to bytesIO objects
    encrypted_file = BytesIO(cipherText)
    encrypted_file.seek(0)
    tag_file = BytesIO(tag)
    tag_file.seek(0)

    # Get the file extension from the original filename
    filename = request.files['file'].filename
    file_extension = filename.rsplit('.', 1)[1].lower()

    # Convert the bytesIO objects to an Image object
    encrypted_image = Image.open(encrypted_file)
    tag_image = Image.open(tag_file)

    # Create a dictionary to hold the response data
    response_data = {
        'encrypted_file': encrypted_image,
        'tag': tag_image
    }

    # Set the appropriate MIME type based on the file extension
    if file_extension == 'png':
        mimetype = 'image/png'
    elif file_extension == 'jpg' or file_extension == 'jpeg':
        mimetype = 'image/jpeg'
    else:
        mimetype = 'application/octet-stream'

    # Return the response as JSON with the appropriate MIME type
    response = jsonify(response_data)
    response.headers.set('Content-Type', mimetype)
    return response