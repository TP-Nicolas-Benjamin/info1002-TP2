from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5

import sys

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

# Transoform a int into a list of 8 bits
def bitfield(n):
    return [1 if digit=='1' else 0 for digit in bin(n)[2:]]

# Transform a list of 8 bits into a int
def bits_to_int(bitlist):
    out = 0
    for bit in bitlist:
        out = (out << 1) | bit
    return out

# Take a byte_array of size 2048 into 256 byte and write it into the picture 
def hideMessage(img: Image.Image, m_bytes: bytearray, start_y: int):
    
    byte_list = list()
    pixels = img.load()
    
    for i in range(len(m_bytes)):
        byte_list += bitfield(m_bytes[i])
    
    for i in range(len(byte_list)//4):
        x = i  
        y = start_y
        print(pixels[x,y])
        r,_,_ = pixels[x,y]
        
        r = 0000 >> r
        r = r << byte_list[i*4]
        r = r << byte_list[i*4 + 1]    
        r = r << byte_list[i*4 + 2]    
        r = r << byte_list[i*4 + 3]    


def findMessage(img: Image.Image, size_message: int, start_y: int):
    
    message = list()
    
    pixels = img.load()

    m_bytes = []

    # On récupère le message
    for i in range(0, size_message, 4):
        x = i
        y = start_y
        r,_,_ = pixels[x,y]
        bit = r & 0b1
        m_bytes.append(bit)
        r = r >> 1
        bit = r & 0b1
        m_bytes.append(bit)
        bit = r & 0b1
        m_bytes.append(bit)
        r = r >> 1
        bit = r & 0b1
        m_bytes.append(bit)
    
    # Split m_bytes into array of 8 bits
    for i in range(0, len(m_bytes)//8, step=8):
        message.append(bits_to_int(m_bytes[i:i+8]))

    return message


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

    private_key = open("private.key", "r")
    private_key = RSA.importKey(private_key.read())
    f.close()

    signer = PKCS1_v1_5.new(private_key)
    digest = SHA512.new()
    digest.update(message)
    sig = signer.sign(digest)

    f = open(f'sign/{filename}.sig', "wb")
    f.write(sig)
    f.close()


def validate_certificate(filename: str):
    f = open(f'certificate/{filename}.png', "rb")
    image_bin = f.read()
    f.close()
    
    f = open(f'sign/{filename}.png.sig', "rb")
    sign = f.read()
    f.close()
    
    return validate_data(image_bin, sign)

def validate_data(data: bytearray, signature: bytearray):
    
    # name_sign = findMessage(img, 512, 1)
    # firstname_sign = findMessage(img, 512, 2)
    
    # cypher_name = findMessage(img, 512, 3)
    # cypher_firstname = findMessage(img, 512, 4)

    hash = SHA512.new()
    
    public_key_file = open("public.key", "r")
    public_key = RSA.importKey(public_key_file.read())
    
    verifier = PKCS1_v1_5.new(public_key)
    
    hash.update(data)
    
    return verifier.verify(hash, signature)
   
def generate_certificate(name: str, firstname: str, score: int):
    
    def text(img, text, x, y, text_size, font="arial", fill=(0,0,0)):
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype(f'fonts/{font}.ttf', text_size)  
        draw.text((x, y), text, fill, font)  

    img = Image.open(f'diplome-BG.png')
    
    text(img, 'UNSC', 255, 100, 15, fill=(0,0,255))
    
    text(img, f'Spartan', 250, 150, 15, fill=(0,128,0))
    
    text(img, f"{name.upper()} {firstname.upper()} a réussi la formation de l'UNSC", 150, 200, 15, fill=(0,0,0))
    
    text(img, f'avec une moyenne de {score}', 200, 250, 15, fill=(0,0,0))
        
    img.save(f'certificate/{name.upper()}_{firstname.upper()}.png')
    sign_certificate(f'{name.upper()}_{firstname.upper()}.png')
    
    
def main(filename, output, message):
    generate_certificate("117", "JOHN", 20)
    print(validate_certificate("117_JOHN"))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)