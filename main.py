from PIL import Image
from Crypto.PublicKey import RSA

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

# def genSigningKey():
#     keyPair = RSA.generate(bits=2048)
#     print("https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples")

def main(filename, output, message):
    # Hide message in picture
    img = Image.open(filename)  # ouverture de l'image contenue dans un fichier
    hideMessage(img, message)
    img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier

    # Find message in picture
    img = Image.open(output)
    msgLength = findMessageLength(img)
    print(f"msgLength : {msgLength}")
    print(findMessage(img, msgLength))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)