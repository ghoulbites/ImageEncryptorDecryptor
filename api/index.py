from flask import Flask, request, send_file, jsonify

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from io import BytesIO
import base64
import os
import io

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
    imageObject = request.files['image']
    image = request.files['image'].read()
    key = request.form['key'].encode()

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

    # Set the output file format to match the input file format
    if imageObject.mimetype == 'image/jpeg':
        output_format = 'image/jpeg'
    elif imageObject.mimetype == 'image/png':
        output_format = 'image/png'

    # Return the encrypted data as a response
    return send_file(output_file, mimetype=output_format)


@app.route('/aes-decrypt', methods=['POST'])
def aesDecrypt():
    # Check if file is in the request
    if 'image' not in request.files:
        return 'No file found', 400

    # Check if key is in the request
    if 'key' not in request.form:
        return 'No key found', 400


    # Read the image and key parameters from the POST request
    imageObject = request.files['image']
    image = request.files['image'].read()
    key = request.form['key'].encode()

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

    # Set the output file format to match the input file format
    if imageObject.mimetype == 'image/jpeg':
        output_format = 'image/jpeg'
    elif imageObject.mimetype == 'image/png':
        output_format = 'image/png'

    # Write the decrypted data to a BytesIO object
    output_file = BytesIO()
    output_file.write(unpadded_data)
    output_file.seek(0)

    # Return the decrypted data as a response
    return send_file(output_file, mimetype=output_format)


@app.route('/rsa-encrypt', methods=['POST'])
def rsaEncrypt():
    # Check if the 'image' and 'key' parameters exist in the form-data
    if 'image' not in request.files or 'key' not in request.form:
        return 'Missing parameters', 400
    
    # Read the image file and key from the form-data
    image_file = request.files['image'].read()
    key = request.form['key']
    
    # Generate a private key
    private_key = RSA.generate(2048)
    
    # Initialize the cipher with the public key
    public_key = private_key.publickey()
    cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the image file
    chunk_size = 470
    encrypted_chunks = []
    for i in range(0, len(image_file), chunk_size):
        chunk = image_file[i:i+chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)
    
    # Base64 encode the encrypted image and private key
    encrypted_image = base64.b64encode(b''.join(encrypted_chunks)).decode()
    encrypted_key = base64.b64encode(private_key.export_key()).decode()
    
    # Return the encrypted image and private key
    return jsonify({
        'encryptedImage': encrypted_image,
        'privateKey': encrypted_key
    })

@app.route('/rsa-decrypt', methods=['POST'])
def rsaDecrypt():
    # Check if the 'image', 'key', and 'privateKey' parameters exist in the form-data
    if 'image' not in request.form or 'key' not in request.form or 'privateKey' not in request.form:
        return 'Missing parameters', 400
    
    # Read the encrypted image and private key from the form-data
    encrypted_image = request.form['image']
    key = request.form['key']
    private_key_str = request.form['privateKey']
    
    # Decode the private key and initialize the cipher
    private_key = RSA.import_key(base64.b64decode(private_key_str))
    cipher = PKCS1_OAEP.new(private_key)
    
    # Decode the encrypted image
    encrypted_image = base64.b64decode(encrypted_image.encode())
    
    # Decrypt the encrypted image
    chunk_size = 512
    decrypted_chunks = []
    for i in range(0, len(encrypted_image), chunk_size):
        chunk = encrypted_image[i:i+chunk_size]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    
    # Combine the decrypted chunks and return the decrypted image
    decrypted_image = b''.join(decrypted_chunks)
    return send_file(io.BytesIO(decrypted_image), mimetype='image/jpeg')