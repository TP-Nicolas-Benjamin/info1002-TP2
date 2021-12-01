from asyncore import read
from fileinput import filename
from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5

import sys
import math
from pprint import pp, pprint
import io

TAILLE = 16

def invert_line(img):
    m = img.height // 2             # milieu de l'image
    pixels = img.load()             # tableau des pixels

    for y in range(m, img.height):
        for x in range(0, img.width):
            # on rÃ©cupÃ¨re les composantes RGB du pixel (x,m)
            r, g, b = pixels[x, y]
            r = r ^ 0b11111111      # on les inverse bit Ã  bit avec un XOR
            g = g ^ 0b11111111      # ...
            b = b ^ 0b11111111      # ...
            # on remet les pixels inversÃ©s dans le tableau
            pixels[x, y] = r, g, b

def get_LSB_of_int(color):
    return color & 1

def stringToBinary(string):
    return ''.join(format(x, '08b') for x in bytearray(string, 'ascii'))

def binaryToString(binary):
    # split fullBin en tableau de binaires de longueur 7
    binTab = [binary[i:i+8] for i in range(0, len(binary), 8)]

    # transforme chanque binaire de taille 7 en un charactère
    msg = ""
    for b in binTab:
        msg += chr(int(b, 2))

    return msg

def hide_message(img, message, y_index):
    # transforme notre message en binaire
    msgBin = stringToBinary(message)
    pixels = img.load()

    msgLengthBin = format(len(message), '016b')

    print("_____ ECRITURE _____")
    print(f"msgBin  = {msgBin}\nmsgBin length  = {len(msgBin)}")

    # inscrit dans le bit de poids faible du rouge de chaque pixel un bit de notre taille de message
    for i in range(TAILLE):
        x = i % img.width
        y = (i // img.width) % img.height
        r,_,_ = pixels[x,y]
        r = (r & ~1) | int(msgLengthBin[x + (x*y)])
        pixels[x,y] = r,_,_

    # inscrit dans le bit de poids faible du rouge de chaque pixel un bit de notre fullbin
    y_index += 1
    for i in range(len(msgBin)):
        x = i % img.width
        y = y_index + (i // img.width) % img.height
        r,_,_ = pixels[x,y]
        r = (r & ~1) | int(msgBin[i])
        pixels[x,y] = r,_,_

def find_message_length(img, y_index):

    pixels = img.load()

    msgLengthBin = ""

    # récupère le bit de poids faible de la couleur rouge de chaque pixels
    for i in range(TAILLE):
        r,_,_ = pixels[i,y_index]
        msgLengthBin += str(get_LSB_of_int(r))

    print("_____ LECTURE TAILLE  _____")   
    print(f"msgLengthBin = {msgLengthBin}\nmsgLengthBin length = {len(msgLengthBin)}")

    print("_____ RESULTAT TAILLE _____")
    return int(msgLengthBin, 2)

def find_message(img, msg_length, y_index):
    
    pixels = img.load()

    fullBin = ""

    # récupère le bit de poids faible de la couleur rouge de chaque pixels
    for i in range(msg_length * 8):
        x = i % img.width
        y = y_index + (i // img.width) % img.height
        r,_,_ = pixels[x,y]
        fullBin += str(get_LSB_of_int(r))

    print("_____ LECTURE MESSAGE  _____")   
    print(f"fullBin = {fullBin}\nfullBin length = {len(fullBin)}")

    print("_____ RESULTAT MESSAGE _____")
    return binaryToString(fullBin)

def generate_pair_key():
    """
    generate_pair_key generate a pair of 2048 bit sized keys
    """
    key=RSA.generate(2048)
    private_key=key.export_key()
    out=open("private.key", "wb")
    out.write(private_key)
    out.close()

    public_key=key.publickey().export_key()
    out=open("public.key", "wb")
    out.write(public_key)
    out.close()


def sign_data(byte_array: bytearray) -> bytearray:
    """
    sign_data sign the byte_array with the private key

    Args:
        byte_array (bytearray): byte_array to sign

    Returns:
        bytearray: signed byte_array
    """
    private_key_file=open("private.key", "r")
    private_key=RSA.importKey(private_key_file.read())
    private_key_file.close()

    signer=PKCS1_v1_5.new(private_key)
    digest=SHA512.new()
    digest.update(bytes(byte_array))
    sig=signer.sign(digest)

    return sig


def sign_file(filename: str):
    """
    sign_file sign the file with the private key

    Args:
        filename (str): file to sign
    """

    f=open(f"certificate/{filename}", "rb")
    message=f.read()
    f.close()

    private_key=open("private.key", "r")
    private_key=RSA.importKey(private_key.read())
    f.close()

    signer=PKCS1_v1_5.new(private_key)
    digest=SHA512.new()
    digest.update(bytes(message))
    sig=signer.sign(digest)

    f=open(f'sign/{filename}.sig', "wb")
    f.write(sig)
    f.close()


def validate_certificate(filename: str) -> bool:
    """
    validate_certificate validate the certificate of the file

    Args:
        filename (str): file to validate

    Returns:
        bool: True if the certificate is valid, False otherwise
    """
    f=open(f'certificate/{filename}', "rb")
    image_bin=f.read()
    f.close()

    f=open(f'sign/{filename}.sig', "rb")
    sign=f.read()
    f.close()

    return validate_data(image_bin, sign)


def validate_hidden_data(filename: str) -> bool:
    """
    validate_hidden_data validate the hidden data of the file

    Args:
        filename (str): file to validate

    Returns:
        bool: True if the hidden data is valid, False otherwise
    """

    filename=f'certificate/{filename}'

    firstname_plain=find_message(filename, 1)
    firstname_sign=find_message(filename, 3)

    firstname_valid=validate_data(firstname_plain, firstname_sign)
    print(f'firstname_valid: {firstname_valid}')

    # name_plain = find_message(filename, 5)
    # name_sign = find_message(filename, 7)

    # name_valid = validate_data(name_plain, name_sign)

    # score_plain = find_message(filename, 9)
    # score_sign = find_message(filename, 11)

    # score_valid = validate_data(score_plain, score_sign)

    # university_footprint = find_message(filename, 13)
    # university_footprint_sign = find_message(filename, 15)

    # university_footprint_valid = validate_data(
    #     university_footprint, university_footprint_sign)

    # return firstname_valid and name_valid and score_valid and university_footprint_valid
    return False


def validate_data(data: bytearray, signature: bytearray) -> bool:
    """
    validate_data validate the data with the public key

    Args:
        data (bytearray): data to validate
        signature (bytearray): signature of the data

    Returns:
        bool: True if the data is valid, False otherwise
    """
    hash=SHA512.new()

    public_key_file=open("public.key", "r")
    public_key=RSA.importKey(public_key_file.read())

    verifier=PKCS1_v1_5.new(public_key)

    hash.update(data)

    try:
        verifier.verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False


def generate_certificate(name: str, firstname: str, score: int):
    """
    generate_certificate generate a certificate for the user and save it in the certificate folder. And sign it with the private key in the sign folder.

    Args:
        name (str): name of the user
        firstname (str): firstname of the user
        score (int): score of the user
    """
    def text(img, text, x, y, text_size, font = "arial", fill = (0, 0, 0)):
        draw=ImageDraw.Draw(img)
        font=ImageFont.truetype(f'fonts/{font}.ttf', text_size)
        draw.text((x, y), text, fill, font)

    img=Image.open(f'diplome-BG.png')

    text(img, 'UNSC', 350, 150, 80, fill = (0, 0, 255))

    text(img, f'Spartan', 380, 270, 50, fill = (0, 128, 0))

    text(img, f"{name.upper()} {firstname.upper()} a réussi la formation de l'UNSC",
         200, 375, 30, fill = (0, 0, 0))

    text(img, f'avec une moyenne de {score}', 325, 425, 30, fill = (0, 0, 0))

    footprint="UNSC Institute of Reach"

    filename=f'{name}_{firstname}.png'

    img_path=f'certificate/{filename}'

    img.save(img_path)

    hide_message(img_path, firstname.encode('ascii'), 1)
    # hide_message(img_path, sign_data(firstname.encode('ascii')), 3)
    # hide_message(img_path, name.encode('ascii'), 5)
    # hide_message(img_path, sign_data(name.encode('ascii')), 7)
    # hide_message(img_path, bitfield(len(bitfield(score, 16)), 16), 9)
    # hide_message(img_path, sign_data(bitfield(score, 16)), 11)
    # hide_message(img_path, footprint.encode('ascii'), 13)
    # hide_message(img_path, sign_data(footprint.encode('ascii')), 15)

    sign_file(filename)


def main(filename, output, message):
    # Hide message in picture
    img = Image.open(filename).convert("RGB")  # ouverture de l'image contenue dans un fichier
    hide_message(img, message, 0)
    img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier

    # Find message in picture
    img = Image.open(output)
    msgLength = find_message_length(img, 0)
    print(f"msgLength : {msgLength}")
    print(find_message(img, msgLength, 1))

    # ------------------------------------------------------------------------------------------

    # generate_certificate("117", "john", 20)
    # print(validate_certificate("117_john.png"))
    # print(validate_hidden_data("117_john.png"))

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)
