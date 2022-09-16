import base64
import numpy as np
from io import BytesIO
from PIL import Image
from aes import AES

def img_to_rgb(img):
    img = Image.open(img)
    arr = np.array(img)

    return arr.flatten(), img.size, img.mode

def rgb_to_bytes(arr):
    return bytes(arr)

def bytes_to_image(b, mode, image_size):
    img = Image.frombytes(mode, image_size, b)

    return img

def image_to_base64(img):
    buffered = BytesIO()
    img.save(buffered, format="JPEG")
    img_str = base64.b64encode(buffered.getvalue())
    return img_str.decode()


aes = AES(b'yellow_submarine', rounds=10)

ctx = aes.encrypt_block(b'yellow_submarine')
print(aes.decrypt_block(ctx))