from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os
from io import BytesIO

app = Flask(__name__)

# Utility Functions 
def derive_key(key, salt):
    # Use SHA256 to derive a 32-byte key from the input key
    h = SHA256.new(key)
    h.update(salt)
    return h.digest()



@app.route('/')
def home():
    return 'Hello, World! This is some random change'


@app.route('/aes-encrypt', methods=['POST'])
def aesEncrypt():
    # Check if file is in the request
    if 'image' not in request.files:
        return 'No file found', 400

    # Check if key is in the request
    if 'key' not in request.form:
        return 'No key found', 400

    # Read the image and key parameters from the POST request
    image = request.files['image'].read()
    key = request.form['key'].encode()
    _, fileExtension = os.path.splitext(secure_filename(request.files['image']))
    print(fileExtension)

    # Generate a salt randomly
    salt = os.urandom(16)

    # Derive a key from the input key using SHA256
    derived_key = derive_key(key, salt)

    # Generate an initialization vector (IV) randomly
    iv = os.urandom(16)

    # Create an AES cipher object with the derived key and IV
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)

    # Pad the input data so that it's a multiple of 16 bytes
    padded_data = image + b"\0" * (16 - len(image) % 16)

    # Encrypt the padded data using AES-CBC mode
    encrypted_data = iv + cipher.encrypt(padded_data)

    # Write the salt and encrypted data to a BytesIO object
    output_file = BytesIO()
    output_file.write(salt)
    output_file.write(encrypted_data)
    output_file.seek(0)

    # Return the encrypted data as a response
    return send_file(output_file, mimetype='application/octet-stream')


@app.route('/aes-decrypt', methods=['POST'])
def aesDecrypt():
    # Check if file is in the request
    if 'image' not in request.files:
        return 'No file found', 400

    # Check if key is in the request
    if 'key' not in request.form:
        return 'No key found', 400


    # Read the image and key parameters from the POST request
    image = request.files['image'].read()
    key = request.form['key'].encode()
    _, fileExtension = os.path.splitext(secure_filename(request.files['image']))
    print(fileExtension)

    # Read the salt and encrypted data from the input file
    salt = image[:16]
    encrypted_data = image[16:]

    # Derive a key from the input key and salt using SHA256
    derived_key = derive_key(key, salt)

    # Extract the IV from the encrypted data
    iv = encrypted_data[:16]

    # Create an AES cipher object with the derived key and IV
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)

    # Decrypt the encrypted data using AES-CBC mode
    decrypted_data = cipher.decrypt(encrypted_data[16:])

    # Remove the padding from the decrypted data
    unpadded_data = decrypted_data.rstrip(b"\0")

    # Write the decrypted data to a BytesIO object
    output_file = BytesIO()
    output_file.write(unpadded_data)
    output_file.seek(0)

    # Return the decrypted data as a response
    return send_file(output_file, mimetype='image/jpeg')