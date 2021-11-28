from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5

import sys

TAILLE = 16

def invert_line(img):
    m = img.height // 2             # milieu de l'image
    pixels = img.load()             # tableau des pixels

    for y in range(m, img.height):
        for x in range(0, img.width):
            r, g, b = pixels[x, y]  # on rÃ©cupÃ¨re les composantes RGB du pixel (x,m)
            r = r ^ 0b11111111      # on les inverse bit Ã  bit avec un XOR
            g = g ^ 0b11111111      # ...
            b = b ^ 0b11111111      # ...
            pixels[x, y] = r, g, b  # on remet les pixels inversÃ©s dans le tableau

def set_bit(value, bit):
    return value | (1<<bit)

def bytesToBinary(mBytes):
    fullBin = ""
    for byte in mBytes:
        fullBin += bin(byte)[2:]
    return fullBin

def bytesToString(bytes):
    msg = ""
    for nb in bytes:
        msg += chr(nb)
    return msg

def hideMessage(img, message):
    mBytes = bytearray(message, "ascii")
    pixels = img.load()

    byteLength = (len(message)).to_bytes(16, byteorder='big')

    min_x = TAILLE % img.width
    min_y = (TAILLE // img.width) % img.height

    # On cache la longueur du message sur les 16 premiers octets
    for i in range(TAILLE):
        x = i % img.width
        y = (i // img.width) % img.height
        r,_,_ = pixels[x,y]
        r = r ^ byteLength[x + (x*y)]
        pixels[x,y] = r,_,_

    # On cache ensuite le message à la suite de sa taille
    for i in range(len(message)):
        x = (min_x + i) % img.width
        y = (min_y + ((min_x + i) // img.width)) % img.height
        print(f"x : {x}, y : {y}")
        print(f"pixels : {pixels[x,y]}")
        r,_,_ = pixels[x,y]
        r = r ^ mBytes[x + (x*y) - TAILLE]
        pixels[x,y] = r,_,_

def findMessageLength(img):
    pixels = img.load()

    mLengthBytes = []

    # On récupère la taille du message sur les 16 premiers bytes
    for i in range(TAILLE):
        x = i % img.width
        y = (i // img.width) % img.height
        r,_,_ = pixels[x,y]
        mLengthBytes.append(r ^ 255)

    return int.from_bytes(mLengthBytes, "big")

def findMessage(img, msg_length):
    pixels = img.load()

    mBytes = []

    min_x = TAILLE % img.width
    min_y = (TAILLE // img.width) % img.height

    # On récupère le message
    for i in range(msg_length):
        x = (min_x + i) % img.width
        y = (min_y + ((min_x + i) // img.width)) % img.height
        r,_,_ = pixels[x,y]
        mBytes.append(r ^ 255)

    msg = bytesToString(mBytes)
    return msg

def generate_pair_key():
    key = RSA.generate(2048)
    private_key = key.export_key()
    out = open("private.key", "wb")
    out.write(private_key)
    out.close()

    public_key = key.publickey().export_key()
    out = open("public.key", "wb")
    out.write(public_key)
    out.close()
    
    
def sign_certificate(filename):
    
    f = open(f"certificate/{filename}", "rb")
    message = f.read()
    f.close()

    key_file = open("private.key", "r")
    private_key = RSA.importKey(key_file.read())
    f.close()

    signer = PKCS1_v1_5.new(private_key)
    digest = SHA512.new()
    digest.update(message)
    sig = signer.sign(digest)

    f = open(f'sign/{filename}.sig', "wb")
    f.write(sig)
    f.close()


def validate_certificate(filename):
    
    f = open(f'certificate/{filename}.png', "rb")
    data = f.read()
    f.close()

    img = Image.open("certificate/"+filename + ".png") 

    name = findMessage(img, 256,1)
    firstname = findMessage(img, 256,2)
    
    digest = SHA512.new()
    digest.update(data)

    f = open(f'sign/{name}_{firstname}.png.sig', "rb")
    sign = f.read()
    f.close()
    
    public_key_file = open("public.key", "r")
    public_key = RSA.importKey(public_key_file.read())
    verifier = PKCS1_v1_5.new(public_key)
    
    return verifier.verify(digest, sign)
   
def generate_certificate(name, firstname, score):
    
    def text(img, text, x, y, text_size, font="arial", fill=(0,0,0)):
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype(f'fonts/{font}.ttf', text_size)  
        draw.text((x, y), text, fill, font)  

    img = Image.open(f'diplome-BG.png')
    
    text(img, 'UNSC', 1020, 400, 60, fill=(0,0,255))
    
    text(img, f'Spartan', 1000, 600, 60, fill=(0,128,0))
    
    text(img, f"{name.upper()} {firstname.upper()} a réussi la formation de l'UNSC", 600, 800, 60, fill=(0,0,0))
    
    text(img, f'avec une moyenne de {score}', 800, 1000, 60, fill=(0,0,0))
    
    img.save(f'certificate/{name.upper()}_{firstname.upper()}.png')
    sign_certificate(f'{name.upper()}_{firstname.upper()}.png')
    
    
def main(filename, output, message):
    validate_certificate("117_JOHN")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)