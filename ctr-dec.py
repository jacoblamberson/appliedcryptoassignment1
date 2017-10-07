import binascii
from multiprocessing import Process
from multiprocessing import Pool
from Crypto.Cipher import AES
import os, random, sys
from binascii import unhexlify


def long_to_bytes (val, endianness='big'):
    """
    Use :ref:`string formatting` and :func:`~binascii.unhexlify` to
    convert ``val``, a :func:`long`, to a byte :func:`str`.

    :param long val: The value to pack

    :param str endianness: The endianness of the result. ``'big'`` for
      big-endian, ``'little'`` for little-endian.

    If you want byte- and word-ordering to differ, you're on your own.

    Using :ref:`string formatting` lets us use Python's C innards.
    """

    # one (1) hex digit per four (4) bits
    width = val.bit_length()

    # unhexlify wants an even multiple of eight (8) bits, but we don't
    # want more digits than we need (hence the ternary-ish 'or')
    width += 8 - ((width % 8) or 8)

    # format width specifier: four (4) bits per hex digit
    fmt = '%%0%dx' % (width // 4)

    # prepend zero (0) to the width, to zero-pad the output
    s = unhexlify(fmt % val)

    if endianness == 'little':
        # see http://stackoverflow.com/a/931095/309233
        s = s[::-1]

    return s


def get_incremented_iv(iv, increment):
    counter = int.from_bytes(binascii.unhexlify(iv), byteorder='big')
    counter += increment
    res = long_to_bytes(counter)
    hex_res = binascii.hexlify(res).decode('utf-8')
    while len(hex_res) < 16:
        hex_res = '0' + hex_res
    return hex_res



def xor_hex_string(a, b):
    c, d = binascii.unhexlify(a), binascii.unhexlify(b)
    result = bxor(c, d)
    return binascii.hexlify(result).decode('utf-8')

def bxor(b1, b2): # use xor for bytes
    result = bytearray()
    for b1, b2 in zip(b1, b2):
        result.append(b1 ^ b2)
    return result

def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.

    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return binascii.hexlify(bytearray(ciphertext)).decode('utf-8')


def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc#.decode('utf-8')

def get_hex_iv():
    return binascii.hexlify(os.urandom(16)).decode('utf-8')

def ctr_encrypt(key, hex, iv):
    last_block = encrypt(key, binascii.unhexlify(iv))
    result = xor_hex_string(last_block, hex)
    return result

def ctr_decrypt(key, hex, iv):
    hold = binascii.hexlify(decrypt(key, iv)).decode('utf-8')
    result = xor_hex_string(hold, hex)
    return result




if __name__ == "__main__":
    input = ""
    output = ""
    keyfile=""
    ivfile =""
    checkiv=0

    for a in range(1,len(sys.argv)):
        if sys.argv[a] == "-k":
            keyfile = sys.argv[a+1]
        if sys.argv[a] == "-v":
            ivfile = sys.argv[a+1]
            checkiv =1
        if sys.argv[a]=="-o":
            output=sys.argv[a+1]
        if sys.argv[a] == "-i":
            input = sys.argv[a + 1]

    infile=open(input,"r")
    hex_data= infile.read()
    infile.close()
    outfile=open(output,"w")
    keyring=open(keyfile,"r")
    key= keyring.read()

    if checkiv:
        ivhold=open(ivfile,"r")
        iv=ivhold.read()

    else:
        iv = binascii.hexlify(hex_data[:32]).decode('utf-8')
    #key = bytes("1234567890abcdef1234567890abcdef", encoding='utf-8')
    #hex_data = binascii.hexlify(bytes("1234567890abcdef", encoding='utf-8')).decode('utf-8')

    last_block=iv
    deanswer=""
    #count=1
    #print(iv)
    #print(iv+1)
    pool = Pool(processes = 4)

    for i in range(0, len(hex_data), 32):
        p = pool.apply_async(ctr_decrypt,(key,hex_data[i:i+32],get_incremented_iv(iv, i)))
        deanswer += p.get()

    outfile.write(deanswer)