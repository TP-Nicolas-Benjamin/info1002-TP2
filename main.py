from PIL import Image
from Crypto.PublicKey import RSA

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

    print(mBytes)

    byteLength = (len(message)*2).to_bytes(16, byteorder='big')
    print(byteLength)
    print(byteLength[15])

    print(f"message length : {len(mBytes)}")
    print(f"img width  : {img.width}")
    print(f"img height : {img.height}")

    for y in range(0, img.height):
        for x in range(0, img.width):
            if(x + (x*y) < len(byteLength)):
                r, g, b = pixels[x,y]
                g = g ^ byteLength[x + (x*y)]
                pixels[x, y] = r, g, b
            else:
                return

    for y in range(0, img.height):
        for x in range(0, img.width):
            if (x + (x*y) < len(mBytes)):
                r, g, b = pixels[x,y]
                r = r ^ int(mBytes[x + (x*y)])
                pixels[x, y] = r, g, b
            else:
                return

def findMessage(img, msg_length):
    pixels = img.load()
    max_x = img.width if msg_length > img.width else msg_length
    max_y = int(msg_length / img.width) + 1

    mBytes = []

    for y in range(max_y):
        for x in range(max_x):
            r, g, b = pixels[x,y]
            mBytes.append(r ^ 255)
            print(mBytes)

    msg = bytesToString(mBytes)
    return msg

def genSigningKey():
    keyPair = RSA.generate(bits=2048)
    print("https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples")

def main(filename, output, message):
    # Hide message in picture
    img = Image.open(filename)  # ouverture de l'image contenue dans un fichier
    hideMessage(img, message)
    # img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier

    # Find message in picture
    # img = Image.open(output)
    # print(findMessage(img, len(message) + 100))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)