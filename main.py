from PIL import Image

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

def hideMessage(img, message):
    mBytes = bytearray(message, "ascii")
    pixels = img.load()

    for x in range(0, len(mBytes)):
        r, g, b = pixels[x,0]
        r = r << mBytes[x]
        r = set_bit(r, ) # ????
        
        # g = mBytes[x]
        # b = mBytes[x]
        pixels[x, 0] = r, g, b

    


def main(filename, output, message):
    img = Image.open(filename)  # ouverture de l'image contenue dans un fichier
    # invert_line(img)
    hideMessage(img, message)
    img.save(output)            # sauvegarde de l'image obtenue dans un autre fichier


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("usage: {} image output".format(sys.argv[0]))
    main(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(1)