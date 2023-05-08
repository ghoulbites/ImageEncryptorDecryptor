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

@app.route('/aes-encrypt', methods=['POST'])
def encrypt():
    # get the image and key from the request
    image = Image.open(request.files['image'])
    key = request.form['key']

    # encrypt the pixel data using AES-GCM
    pixels = image.load()
    width, height = image.size
    nonce = get_random_bytes(12)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_GCM, nonce=nonce)
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            rgb = bytes([r, g, b])
            cipherText, tag = cipher.encrypt_and_digest(rgb)
            pixels[x, y] = tuple(cipherText)

    # create an in-memory buffer for the encrypted image file
    buffer = BytesIO()
    image.save(buffer, format=image.format)

    # set the buffer's file pointer to the beginning of the buffer
    buffer.seek(0)

    # Return the buffer as a response with the appropriate MIME type
    return send_file(
        buffer,
        mimetype='image/' + image.format.lower(),
        as_attachment=True,
        attachment_filename='encrypted_image.' + image.format.lower()
    )