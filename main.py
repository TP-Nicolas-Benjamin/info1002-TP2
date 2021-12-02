from PIL import Image
from PIL import ImageFont
from PIL import ImageDraw

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import PKCS1_v1_5

import sys

# Size of stored length in bits
TAILLE = 16


def invert_line(img: Image.Image) -> None:
    """
    invert_line invert half of the image

    Args:
        img (Image.Image): image to invert
    """
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


def get_LSB_of_int(color: int) -> int:
    """
    get_LSB_of_int get low bit of an int

    Args:
        color (int): int to get the low bit

    Returns:
        int: lowest bit of the int
    """
    return color & 1


def bytes_to_binary(b: bytes) -> bytes:
    """
    bytes_to_binary convert a bytes to a binary string

    Args:
        b (bytes): bytes to convert

    Returns:
        bytes: binary string converted
    """
    tmp = b.hex()
    return bin(int(tmp, 16))[2:].zfill(8)


def string_to_binary(string: str) -> bytes:
    """
    string_to_binary convert a string to a binary string

    Args:
        string (str): string to convert

    Returns:
        bytes: binary string converted
    """
    return ''.join(format(x, '08b') for x in bytearray(string, 'utf-8'))


def binary_to_string(binary: bytes) -> str:
    """
    binary_to_string convert a binary string to a string

    Args:
        binary (bytes): binary string to convert

    Returns:
        str: string converted
    """

    # Split the binary string into 8-bit chunks
    binTab = [binary[i:i+8] for i in range(0, len(binary), 8)]

    # Convert each 8-bit chunk into a string
    msg = ""
    for b in binTab:
        msg += chr(int(b, 2))

    return msg


def hide_bytes(img: Image.Image, b: bytes, y_index: int):
    """
    hide_bytes hide the bytes in the image at (0,y_index)

    Args:
        img (Image.Image): image to hide the bytes
        b (bytes): bytes to hide
        y_index (int): y index in the image to hide the bytes
    """

    msgBin = bytes_to_binary(b)
    hide_binary(img, b, msgBin, y_index)


def hide_message(img: Image.Image, message: str, y_index: int):
    """
    hide_message hide the message in the image at (0,y_index)

    Args:
        img (Image.Image): image to hide the message
        message (str): message to hide
        y_index (int): y index in the image to hide the message
    """
    msgBin = string_to_binary(message)
    hide_binary(img, message, msgBin, y_index)


def hide_binary(img: Image.Image, message: str, binary: bytes, y_index: int):
    """
    hide_binary hide the binary in the image at (0,y_index)

    Args:
        img (Image.Image): image to hide the binary
        message (str): used to know the length of the binary
        binary (bytes): binary to hide
        y_index (int): y index in the image to hide the binary
    """

    pixels = img.load()

    msgLengthBin = format(len(message), '016b')

    # inscrit dans le bit de poids faible du rouge de chaque pixel un bit de notre taille de message
    for i in range(TAILLE):
        x = i % img.width
        y = y_index
        r, _, _ = pixels[x, y]
        r = (r & ~1) | int(msgLengthBin[i])
        pixels[x, y] = r, _, _

    for i in range(len(binary)):
        x = i % img.width
        y = y_index + 1 + (i // img.width) % img.height
        r, _, _ = pixels[x, y]
        r = (r & ~1) | int(binary[i])
        pixels[x, y] = r, _, _


def find_message_length(img, y_index):

    pixels = img.load()

    msgLengthBin = ""

    # récupère le bit de poids faible de la couleur rouge de chaque pixels
    for i in range(TAILLE):
        r, _, _ = pixels[i, y_index]
        msgLengthBin += str(get_LSB_of_int(r))

    return int(msgLengthBin, 2)


def find_message(img: Image.Image, msg_length: int, y_index: int) -> str:
    """
    find_message find the message of size msg_length at (0,y_index) in the image and return it

    Args:
        img (Image.Image): image to search
        msg_length (int): size of the message to find
        y_index (int): y index of the message to find

    Returns:
        str: message found
    """
    pixels = img.load()

    fullBin = ""

    # Get the lower bits of the red color of each pixel
    for i in range(msg_length * 8):
        x = i % img.width
        y = y_index + (i // img.width) % img.height
        r, _, _ = pixels[x, y]

        fullBin += str(get_LSB_of_int(r))

    return binary_to_string(fullBin)


def generate_pair_key():
    """
    generate_pair_key generate a pair of 2048 bit sized keys
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    out = open("private.key", "wb")
    out.write(private_key)
    out.close()

    public_key = key.publickey().export_key()
    out = open("public.key", "wb")
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
    private_key_file = open("private.key", "r")
    private_key = RSA.importKey(private_key_file.read())
    private_key_file.close()

    signer = PKCS1_v1_5.new(private_key)
    digest = SHA512.new(byte_array)
    print(len(digest.digest()))
    sig = signer.sign(digest)
    return sig


def sign_file(filename: str):
    """
    sign_file sign the file with the private key

    Args:
        filename (str): file to sign
    """

    f = open(f"certificate/{filename}", "rb")
    message = f.read()
    f.close()

    private_key = open("private.key", "r")
    private_key = RSA.importKey(private_key.read())
    f.close()

    signer = PKCS1_v1_5.new(private_key)
    digest = SHA512.new()
    digest.update(bytes(message))
    sig = signer.sign(digest)

    f = open(f'sign/{filename}.sig', "wb")
    f.write(sig)
    f.close()


def validate_certificate(filename: str, signature: str) -> bool:
    """
    validate_certificate validate the certificate of the file

    Args:
        filename (str): file to validate
        signature (str): signature of the file

    Returns:
        bool: True if the certificate is valid, False otherwise
    """
    f = open(f'certificate/{filename}', "rb")
    image_bin = f.read()
    f.close()

    f = open(f'sign/{signature}', "rb")
    sign = f.read()
    f.close()

    return validate_data(image_bin, sign) and validate_hidden_data(filename)


def validate_hidden_data(filename: str) -> bool:
    """
    validate_hidden_data validate the hidden data of the file

    Args:
        filename (str): file to validate

    Returns:
        bool: True if the hidden data is valid, False otherwise
    """

    filename = f'certificate/{filename}'

    img = Image.open(filename)

    msgLength = find_message_length(img, 0)
    firstname_plain = find_message(img, msgLength, 1)

    msgLength = find_message_length(img, 10)
    firstname_sign = find_message(img, msgLength, 11)

    print('message length: ' + str(msgLength))
    print('firstname_sign len: ', len(firstname_sign))
    print('firstname_plain ', firstname_plain)

    print('firstname_sign ', firstname_sign)
    firstname_valid = validate_data(
        firstname_plain.encode('utf-8'), firstname_sign.encode('utf-8'))

    print(firstname_valid)

    # if firstname_valid:
    #     print("firstname valid")
    # else:
    #     print("firstname invalid")

    # msgLength = find_message_length(img, 20)
    # name_plain = find_message(img, msgLength, 21)

    # msgLength = find_message_length(img, 30)
    # name_sign = find_message(img, msgLength, 31)

    # name_valid = validate_data(name_plain.encode(
    #     "utf-8"), name_sign.encode("utf-8"))

    # if name_valid:
    #     print("name valid")
    # else:
    #     print("name invalid")

    # msgLength = find_message_length(img, 40)
    # score_plain = find_message(img, msgLength, 41)

    # msgLength = find_message_length(img, 50)
    # score_sign = find_message(img, msgLength, 51)

    # score_valid = validate_data(score_plain.encode(
    #     "utf-8"), score_sign.encode("utf-8"))

    # if score_valid:
    #     print("score valid")
    # else:
    #     print("score invalid")

    # msgLength = find_message_length(img, 60)
    # university_footprint = find_message(img, msgLength, 61)

    # msgLength = find_message_length(img, 70)
    # university_footprint_sign = find_message(img, msgLength, 71)

    # university_footprint_valid = validate_data(
    #     university_footprint.encode("utf-8"), university_footprint_sign.encode("utf-8"))

    # if university_footprint_valid:
    #     print("university footprint valid")
    # else:
    #     print("university footprint invalid")

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
    hash = SHA512.new(data)

    public_key_file = open("public.key", "r")
    public_key = RSA.importKey(public_key_file.read())

    verifier = PKCS1_v1_5.new(public_key)

    print("data ", hash.digest().hex())
    print("signature ", len(signature))

    return verifier.verify(hash, signature)


def generate_certificate(name: str, firstname: str, score: int):
    """
    generate_certificate generate a certificate for the user and save it in the certificate folder. And sign it with the private key in the sign folder.

    Args:
        name (str): name of the user
        firstname (str): firstname of the user
        score (int): score of the user
    """
    def text(img, text, x, y, text_size, font="arial", fill=(0, 0, 0)):
        draw = ImageDraw.Draw(img)
        font = ImageFont.truetype(f'fonts/{font}.ttf', text_size)
        draw.text((x, y), text, fill, font)

    img = Image.open('diplome-BG.png').convert("RGB")

    text(img, 'UNSC', 350, 150, 80, fill=(0, 0, 255))

    text(img, f'Spartan', 380, 270, 50, fill=(0, 128, 0))

    text(img, f"{name.upper()} {firstname.upper()} a réussi la formation de l'UNSC",
         200, 375, 30, fill=(0, 0, 0))

    text(img, f'avec une moyenne de {score}', 325, 425, 30, fill=(0, 0, 0))

    footprint = "UNSC Institute of Reach"

    filename = f'{name}_{firstname}.png'

    img_path = f'certificate/{filename}'

    hide_message(img, firstname, 0)
    hide_bytes(img, sign_data(firstname.encode('utf-8')), 10)

    hide_message(img, name, 20)
    hide_bytes(img, sign_data(name.encode('utf-8')), 30)

    hide_message(img, str(score), 40)
    hide_bytes(img, sign_data(str(score).encode("utf-8")), 50)

    hide_message(img, footprint, 60)
    hide_bytes(img, sign_data(footprint.encode('utf-8')), 70)

    img.save(img_path)

    sign_file(filename)


def help():
    return """Usage: python3 main.py [commands] [arguments]
Commands available :
--help: print this help
--generate: generate a certificate for the user and save it in the certificate folder. And sign it with the private key in the sign folder.
    [arguments]: <name>  <firstname> <score>
    [example]: python3 main.py --generate "Doe" "John" 20
    [output]: certificate/John_Doe.png and sign/John_Doe.png

--validate: validate the certificate of the user
    [arguments]: <filename> of the certificate to validate and the signature of the certificate (<filename>.png.sign). Files are directly in the certificate folder, no needs to add ./certificate.
    [example]: python3 main.py --validate "John_Doe.png" "John_Doe.png.sign"
    [output]: True or False

--validate-hidden: validate the hidden data of the certificate of the user
    [arguments]: <filename> of the certificate to validate
    [example]: python3 main.py --validate-hidden "John_Doe.png"
    [output]: True or False

--read: read the message in the picture at the position <position> and print it
    [arguments]: <filename> of the picture and the position of the message
    [example]: python3 main.py --read "John_Doe.png" 0
    [output]: John

--hide-message: hide the message in the picture at the position <position>
    [arguments]: <filename> of the picture and the position of the message and the message to hide
    [example]: python3 main.py --hide-message "John_Doe.png" 0 "John"
    [output]: John_Doe.png

--pair: generate a pair of keys and save them in the folder
    [arguments]: None
    [example]: python3 main.py --pair
    [output]: ./public.key and ./private.key

"""


if __name__ == "__main__":
    # If no args are given, print the help
    if len(sys.argv) == 1:
        print(help())
        exit(1)
    for arg in sys.argv:
        if arg == "--help":
            print(help())
            exit(0)
        if arg == "--generate":
            if len(sys.argv) == 5:
                name = sys.argv[2]
                firstname = sys.argv[3]
                score = int(sys.argv[4])
                generate_certificate(name, firstname, score)
                exit(0)
            else:
                print("""Error: --generate requires 3 arguments
    [arguments]: <name>  <firstname> <score>
    [example]: python3 main.py --generate "Doe" "John" 20
    [output]: certificate/John_Doe.png and sign/John_Doe.png
""")
                exit(1)
        if arg == "--validate":
            if len(sys.argv) == 4:
                filename = sys.argv[2]
                signature = sys.argv[3]
                print(validate_certificate(filename, signature))
                exit(0)
            else:
                print("""Error: --validate requires 2 arguments
    [arguments]: <filename> of the certificate to validate and the signature of the certificate (<filename>.png.sign). Files are directly in the certificate folder, no needs to add ./certificate.
    [example]: python3 main.py --validate "John_Doe.png" "John_Doe.png.sign"
    [output]: True or False""")
                exit(1)
        if arg == "--validate-hidden":
            if len(sys.argv) == 3:
                filename = sys.argv[2]
                print(validate_hidden_data(filename))
                exit(0)
            else:
                print("""Error: --validate-hidden requires 2 arguments
    [arguments]: <filename> of the certificate to validate]
    [example]: python3 main.py --validate-hidden "John_Doe.png"]
    [output]: True or False""")
                exit(1)
        if arg == "--read":
            if len(sys.argv) == 4:
                filename = sys.argv[2]
                line = int(sys.argv[3])
                img = Image.open(filename)
                size = find_message_length(img, line)
                print(f"Size message found: {size}")
                print(find_message(img, size, line + 1))
                exit(0)
            else:
                print("""Error: --read requires 2 arguments
    [arguments]: <filename> of the picture and the position of the message
    [example]: python3 main.py --read "John_Doe.png" 0
    [output]: John""")
                exit(1)
        if arg == "--hide-message":
            if len(sys.argv) == 5:
                filename = sys.argv[2]
                line = int(sys.argv[3])
                message = sys.argv[4]
                img = Image.open(filename)
                hide_message(img, message, int(line))
                print(f"Message {message} hidden in {filename} at line {line}")
                img.save(filename)
                exit(0)
            else:
                print("""Error: --hide-message requires 3 arguments
    [arguments]: <filename> of the picture and the position of the message and the message to hide
    [example]: python3 main.py --hide-message "John_Doe.png" 0 "John"
    [output]: John_Doe.png""")
                exit(1)
        if arg == "--pair":
            if len(sys.argv) == 2:
                generate_pair_key()
                print("Keys generated")
                exit(0)
            else:
                print("""Error: --pair requires 2 arguments
    [arguments]: None
    [example]: python3 main.py --pair
    [output]: ./public.key and ./private.key""")
                exit(1)
