from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from io import BytesIO
from PIL import Image
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
    # Get the image file and key from the request
    image_file = request.files['image'].read()
    key = request.form['key']

    # Generate RSA key pair
    rsa_key = RSA.generate(2048)

    # Encrypt the image file with RSA
    cipher = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)
    encrypted_image = cipher.encrypt(image_file)

    # Encrypt the RSA private key with AES
    encrypted_key = key.encode('utf-8')
    rsa_private_key = rsa_key.export_key('PEM')
    cipher = AES.new(encrypted_key, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_rsa_private_key, tag = cipher.encrypt_and_digest(rsa_private_key)

    # Return the encrypted image file and private key
    file_extension = os.path.splitext(request.files['image'].filename)[1]
    return {
        'privateKey': {
            'encryptedKey': encrypted_key.hex(),
            'nonce': nonce.hex(),
            'encryptedRSAKey': encrypted_rsa_private_key.hex(),
            'tag': tag.hex()
        },
        'encryptedImage': encrypted_image.hex(),
        'fileExtension': file_extension
    }


@app.route('/rsa-decrypt', methods=['POST'])
def rsaDecrypt():
    # Get the encrypted image file, key, and private key from the request
    encrypted_image = bytes.fromhex(request.files['image'].read().decode('utf-8'))
    key = request.form['key']
    encrypted_key = bytes.fromhex(request.form['privateKey']['encryptedKey'])
    nonce = bytes.fromhex(request.form['privateKey']['nonce'])
    encrypted_rsa_private_key = bytes.fromhex(request.form['privateKey']['encryptedRSAKey'])
    tag = bytes.fromhex(request.form['privateKey']['tag'])

    # Decrypt the RSA private key with AES
    cipher = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    rsa_private_key = cipher.decrypt_and_verify(encrypted_rsa_private_key, tag)
    rsa_key = RSA.import_key(rsa_private_key)

    # Decrypt the image file with RSA
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted_image = cipher.decrypt(encrypted_image)

    # Save the decrypted image file to memory
    file_extension = request.form['fileExtension']
    image = Image.open(io.BytesIO(decrypted_image))
    output = io.BytesIO()
    image.save(output, format=file_extension)

    # Return the decrypted image file
    output.seek(0)
    return send_file(output, mimetype='image/' + file_extension[1:])
