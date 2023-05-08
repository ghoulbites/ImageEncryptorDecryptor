from flask import Flask, request, send_file, jsonify
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from io import BytesIO
import os


app = Flask(__name__)

# Utility Functions 
def derive_key(key, salt):
    # Use SHA256 to derive a 32-byte key from the input key
    h = SHA256.new(key)
    h.update(salt)
    return h.digest()

# For RSA
def generate_keys(key_size):
    # Generate RSA key pair of given key size
    key = RSA.generate(key_size)
    #! DEBUG: Print the private key to the terminal
    # print(f"Private key: (n={hex(key.n)}, d={hex(key.d)})")
    return key

def encrypt_chunk(chunk, key):
    # Encrypt the chunk with RSA
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_chunk = cipher_rsa.encrypt(chunk)
    return encrypted_chunk

def decrypt_chunk(encrypted_chunk, key):
    # Decrypt the chunk with RSA
    cipher_rsa = PKCS1_OAEP.new(key)
    chunk = cipher_rsa.decrypt(encrypted_chunk)
    return chunk

def encrypt_image(file, key):
    # Encrypt the image file with RSA
    encrypted_bytes = BytesIO()

    while True:
        chunk = file.read(key.size_in_bytes() - 42)
        if not chunk:
            break
        encrypted_chunk = encrypt_chunk(chunk, key.publickey())
        encrypted_bytes.write(encrypted_chunk)

    encrypted_bytes.seek(0)
    return encrypted_bytes.getvalue()

def decrypt_image(file, private_key):
    # Decrypt the image file with RSA
    decrypted_bytes = BytesIO()

    while True:
        encrypted_chunk = file.read(private_key.size_in_bytes())
        if not encrypted_chunk:
            break
        chunk = decrypt_chunk(encrypted_chunk, private_key)
        decrypted_bytes.write(chunk)

    decrypted_bytes.seek(0)
    return decrypted_bytes.getvalue()



#? Endpoints

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
    # Check if file was uploaded
    if 'image' not in request.files:
        return 'No file provided', 400

    image = request.files['image']

    # Check if file is an image
    if not image.content_type.startswith('image/'):
        return 'Only image files are allowed', 400

    # Generate RSA key pair
    key = generate_keys(2048)

    # Encrypt the image file with RSA
    encrypted_data = encrypt_image(image, key)

    if image.mimetype == 'image/jpeg':
        output_format = 'image/jpeg'
    elif image.mimetype == 'image/png':
        output_format = 'image/png'

    # Return the encrypted file and private key
    return (
        send_file(BytesIO(encrypted_data), mimetype=output_format, as_attachment=False),
        key.export_key()
    )

@app.route('/rsa-decrypt', methods=['POST'])
def rsaDecrypt():
    # Check if file was uploaded
    if 'image' not in request.files:
        return 'No file provided', 400

    image = request.files['image']

    # Check if file is an image
    if not image.content_type.startswith('image/'):
        return 'Only image files are allowed', 400

    # Check if private key was uploaded
    if 'key' not in request.form:
        return 'No private key provided', 400

    private_key = RSA.import_key(request.form['key'])

    # Decrypt the image file with RSA
    decrypted_data = decrypt_image(image, private_key)

    if image.mimetype == 'image/jpeg':
        output_format = 'image/jpeg'
    elif image.mimetype == 'image/png':
        output_format = 'image/png'

    # Return the decrypted file
    return send_file(BytesIO(decrypted_data), mimetype=output_format, as_attachment=False)
