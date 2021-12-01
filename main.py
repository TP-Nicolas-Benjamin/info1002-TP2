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


def bitfield(n: int, size_bytearray: int) -> bytearray:
    """
    bitfield convert an int to a bytearray of size_bytearray

    Args:
        n (int): int to convert
        size_bytearray (int): size of the bytearray

    Returns:
        bytearray: bytearray of size_bytearray
    """
    bit_list = bytearray()
    bit_list = [1 if digit == '1' else 0 for digit in bin(n)[2:]]
    if size_bytearray - len(bit_list) != 0:
        bit_list = [0] * (size_bytearray - len(bit_list)) + bit_list

    return bit_list


def bits_to_int(bit_list: bytearray, delimiter: int) -> list[int]:
    """
    bits_to_int convert a bytearray to  delimitered size int list

    Args:
        bit_list (bytearray): bytearray to convert
        delimiter (int): size of the delimited int

    Returns:
        list[int]: int list
    """
    i = 0
    res = list()
    out = 0
    bit_list.reverse()
    bit_list = list(chunks(bit_list, delimiter))
    for chk in bit_list:
        for bit in chk:
            out += bit << i
            i += 1
        res += [out]
        out = 0
        i = 0
    res.reverse()
    return res


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def hide_message(filename: str, m_bytes: bytearray, start_y: int) -> None:
    """
    hide_message in filemane image the message m_bytes in the line start_y

    Args:
        filename (str): image filename
        m_bytes (bytearray): message to hide
        start_y (int): line where the size of the message is hidden, next line is the message itself
    """

    size_message = len(m_bytes)*2
    size_message_bin = bitfield(size_message, 16)
    part_size_message_bin = list(chunks(size_message_bin, 4))

    img = Image.open(filename)
    pixels = img.load()

    # Write the size of the message in the start_y line
    for i in range(0, 4):
        r, g, b = pixels[i, start_y]
        r = (r >> 4) << 4
        print(f'part_size_message_bin[i]: {part_size_message_bin[i]}'))
        r=r ^ bits_to_int(part_size_message_bin[i], 4)[0]
        pixels[i, start_y]=r, g, b

    print(len(m_bytes), "bytes")
    # Write 4 byte by 4 byte the message in the next line
    for i in range(0, size_message):
        r, g, b=pixels[i, start_y + 1]

        r=(r >> 4) << 4

        if i % 2 == 0:
            r=r ^ ((m_bytes[i//2] >> 4) & 0b00001111)
        else:
            r=r ^ (m_bytes[i//2] & 0b00001111)
        pixels[i, start_y + 1]=r, g, b
        print("after ", r)

    img.save(filename+"_out.png")


def find_message(filename: str, start_y: int) -> bytearray:
    """
    Given a line, find the size of the message and the message in the next line

    Args:
        filename (str): image filename
        start_y (int): Line where the size of the message is hidden, next line is the message itself

    Returns:
        bytearray: message
    """
    message=list()

    print(f"file: {filename}_out.png")
    img=Image.open(filename)

    pixels=img.load()

    # Read the size of the message
    size_message_bin=list()
    for i in range(0, 4):
        r, g, b=pixels[i, start_y]
        size_message_bin += [r & 0b00001111]
    size=size_message_bin[0] << 12 | size_message_bin[1] << 8 | size_message_bin[2] << 4 | size_message_bin[3]
    print(f'size: {size}')
    # Read 4 byte by 4 byte the message in the next line
    message_part=list()
    for i in range(0, size):
        r, g, b=pixels[i, start_y + 1]
        print(r)
        message_part += [r & 0b00001111]
    print(message_part)
    for i in range(0, size, 2):
        message += [message_part[i] << 4 | 0b00001111 & message_part[i + 1]]

    print(f"message: {message}")

    print(f'size_message: {size}')
    return message


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
    # generate_certificate("117", "john", 20)
    # print(validate_certificate("117_john.png"))
    # print(validate_hidden_data("117_john.png"))
    print(bitfield(4, 4))
    print(bits_to_int([1, 0, 0, 1, 1, 0, 0, 0], 4))
    hide_message("certificate/117_john.png", "TEST".encode('ascii'), 1)
    find_message("certificate/117_john.png", 1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)
