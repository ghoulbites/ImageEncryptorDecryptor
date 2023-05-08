from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from io import BytesIO
from PIL import Image
import os

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
    # Check if the request contains an image file
    if 'image' not in request.files:
        return jsonify({'error': 'No image file in request'}), 400

    # Check if the request contains a key parameter
    if 'key' not in request.form:
        return jsonify({'error': 'No key parameter in request'}), 400

    # Read the image file from the request
    image_file = request.files['image'].read()

    # Check if the image file is a JPEG/JPG or a PNG
    if not Image.open(io.BytesIO(image_file)).format.lower() in ('jpeg', 'jpg', 'png'):
        return jsonify({'error': 'Unsupported image format'}), 400

    # Generate an RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key(passphrase=request.form['key'])

    # Encrypt the image file with the public key
    cipher = PKCS1_OAEP.new(key.publickey())
    encrypted_image = cipher.encrypt(image_file)

    # Create a response containing the encrypted image and the private key
    response = jsonify({
        'encrypted_image': encrypted_image,
        'private_key': private_key
    })

    # Set the content type to binary data
    response.headers.set('Content-Type', 'application/octet-stream')

    return response, 200


@app.route('/rsa-decrypt', methods=['POST'])
def rsaDecrypt():
    # Check if the request contains an image file
    if 'image' not in request.files:
        return jsonify({'error': 'No image file in request'}), 400

    # Check if the request contains a key parameter
    if 'key' not in request.form:
        return jsonify({'error': 'No key parameter in request'}), 400

    # Check if the request contains a privateKey parameter
    if 'privateKey' not in request.form:
        return jsonify({'error': 'No privateKey parameter in request'}), 400

    # Read the encrypted image file and the private key from the request
    encrypted_image = request.files['image'].read()
    encrypted_private_key = request.form['privateKey'].encode('utf-8')

    # Decrypt the private key with the provided passphrase
    key = RSA.import_key(encrypted_private_key, passphrase=request.form['key'])

    # Decrypt the image file with the private key
    cipher = PKCS1_OAEP.new(key)
    image_file = cipher.decrypt(encrypted_image)

    # Check if the image file is a JPEG/JPG or a PNG
    if not Image.open(io.BytesIO(image_file)).format.lower() in ('jpeg', 'jpg', 'png'):
        return jsonify({'error': 'Unsupported image format'}), 400

    # Create a response containing the decrypted image file
    response = jsonify({'decrypted_image': image_file})

    # Set the content type to the same format as the input image
    response.headers.set('Content-Type', 'image/' + Image.open(io.BytesIO(image_file)).format.lower())

    return response, 200
