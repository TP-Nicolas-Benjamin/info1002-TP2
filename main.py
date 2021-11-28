from PIL import Image
from Crypto.PublicKey import RSA
from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw

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

def get_LSB_of_int(color):
    return color & 1

def stringToBinary(string):
    return ''.join(format(x, '07b') for x in bytearray(string, 'utf-8'))

def binaryToString(binary):
    # split fullBin en tableau de binaires de longueur 7
    binTab = [binary[i:i+7] for i in range(0, len(binary), 7)]

    # transforme chanque binaire de taille 7 en un charactère
    msg = ""
    for b in binTab:
        msg += chr(int(b, 2))

    return msg

# def hide_message_Q1(img, message):
#     mBytes = bytearray(message, "ascii")
#     pixels = img.load()

#     byteLength = (len(message)).to_bytes(16, byteorder='big')

#     min_x = TAILLE % img.width
#     min_y = (TAILLE // img.width) % img.height

#     # On cache la longueur du message sur les 16 premiers octets
#     for i in range(TAILLE):
#         x = i % img.width
#         y = (i // img.width) % img.height
#         r,_,_ = pixels[x,y]
#         r = r ^ byteLength[x + (x*y)]
#         pixels[x,y] = r,_,_

#     # On cache ensuite le message à la suite de sa taille
#     for i in range(len(message)):
#         x = (min_x + i) % img.width
#         y = (min_y + ((min_x + i) // img.width)) % img.height
#         r,_,_ = pixels[x,y]
#         r = r ^ mBytes[x + (x*y) - TAILLE]
#         pixels[x,y] = r,_,_

# def findMessageLength(img):
#     pixels = img.load()

#     mLengthBytes = []

#     # On récupère la taille du message sur les 16 premiers bytes
#     for i in range(TAILLE):
#         x = i % img.width
#         y = (i // img.width) % img.height
#         r,_,_ = pixels[x,y]
#         mLengthBytes.append(r ^ 255)

#     return int.from_bytes(mLengthBytes, "big")

# def find_message_Q1(img, msg_length):
#     pixels = img.load()

#     mBytes = []

#     min_x = TAILLE % img.width
#     min_y = (TAILLE // img.width) % img.height

#     # On récupère le message
#     for i in range(msg_length):
#         x = (min_x + i) % img.width
#         y = (min_y + ((min_x + i) // img.width)) % img.height
#         r,_,_ = pixels[x,y]
#         mBytes.append(r ^ 255)

#     msg = bytesToString(mBytes)
#     return msg

def hideMessage(img, message, y_index):
    # transforme notre message en binaire
    msgBin = stringToBinary(message)
    pixels = img.load()

    print("_____ ECRITURE _____")
    print(f"msgBin  = {msgBin}\nmsgBin length  = {len(msgBin)}")

    # inscrit dans le bit de poids faible du rouge de chaque pixel un bit de notre fullbin
    for i in range(len(msgBin)):
        r,_,_ = pixels[i,y_index]
        r = (r & ~1) | int(msgBin[i])
        pixels[i,y_index] = r,_,_

def findMessage(img, y_index, x_max):
    pixels = img.load()

    fullBin = ""

    # récupère le bit de poids faible de la couleur rouge de chaque pixels
    for i in range(x_max * 7):
        r,_,_ = pixels[i,y_index]
        fullBin += str(get_LSB_of_int(r))

    print("_____ LECTURE  _____")   
    print(f"fullBin = {fullBin}\nfullBin length = {len(fullBin)}")

    print("_____ RESULTAT _____")
    return binaryToString(fullBin)

def add_text(img, text):
    W, H = (img.width, img.height)
    draw = ImageDraw.Draw(img)                  # objet "dessin" dans l'image
    w, h = draw.textsize(text)
    font = ImageFont.truetype("sans.ttf", 32)   # police à utiliser
    draw.text(((W-w)/2,(H-h)/2), text, "white", font)

def main(filename, output, message):
# Question 1 : cacher un message et le retrouver
    # Hide message in picture
    img = Image.open(filename).convert("RGB")  # ouverture de l'image contenue dans un fichier
    hideMessage(img, message, 0)
    img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier

    # Find message in picture
    img = Image.open(output)
    print(findMessage(img, 0, len(message)))

# Question 2 : encrypter des données
# TODO: BEN

# Question 3 : écrire sur un document (image dans notre cas)
    add_text(img, "Nicolas")
    img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier

# Question 4 : générer un diplome avec une donnée cacher, une donnée signée et le nom de l'étudiant et sa moyenne
# TODO:

# Question 5 : extraire ces informations
# TODO:

# Version pour cacher le message avec sa taille avant
    # # Hide message in picture
    # img = Image.open(filename).convert("RGB")  # ouverture de l'image contenue dans un fichier
    # hide_message_Q1(img, message)
    # img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier
    # # Find message in picture
    # msgLength = findMessageLength(img)
    # print(f"msgLength : {msgLength}")
    # print(find_message_Q1(img, msgLength))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)