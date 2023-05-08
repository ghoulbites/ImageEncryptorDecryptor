from flask import Flask, request, send_file, jsonify
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import hashlib
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
    # Get the image file and key from the request
    image_file = request.files['image']
    key = request.form['key']
    
    # Hash the key using SHA-256 and get the first 32 bytes as the AES key
    hashed_key = hashlib.sha256(key.encode()).digest()[:32]
    
    # Read the image file and convert it to bytes
    image_bytes = BytesIO(image_file.read())

    # Open the image using Pillow and encrypt it with AES-GCM
    with Image.open(image_bytes) as im:
        # Get the file extension and determine the output format
        file_ext = im.format.lower()
        if file_ext == 'jpeg':
            output_format = 'JPEG'
        elif file_ext == 'png':
            output_format = 'PNG'
        else:
            output_format = 'BMP'
        
        # Encrypt the image with AES-GCM
        nonce = get_random_bytes(12)
        cipher = AES.new(hashed_key, AES.MODE_GCM, nonce=nonce)
        cipherText, tag = cipher.encrypt_and_digest(pad(im.tobytes(), AES.block_size))

        # Create a new image from the encrypted data
        encrypted_image = Image.frombytes(im.mode, im.size, cipherText)

        # Create an in-memory file object for the encrypted image
        output_buffer = BytesIO()
        encrypted_image.save(output_buffer, format=output_format)
        encrypted_image_bytes = output_buffer.getvalue()

        # Set the appropriate MIME type based on the file extension
        if file_ext == 'png':
            mimetype = 'image/png'
        elif file_ext == 'jpg' or file_ext == 'jpeg':
            mimetype = 'image/jpeg'
        else:
            mimetype = 'application/octet-stream'

    # Return the encrypted image and tag as a JSON response
    response = {
        'image': encrypted_image_bytes,
        'tag': tag.hex()
    }
    response.headers.set('Content-Type', mimetype)
    return jsonify(response)