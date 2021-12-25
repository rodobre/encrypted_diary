from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import bcrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode
from datetime import datetime
from os.path import isfile
from sys import exit
from getpass import getpass

DIARY_PATH = "./.diary"
DIARY_SALT_PATH = "./.diary_salt"


def encrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt with PKCS padding
    return cipher.encrypt(pad(data, 16))


def decrypt_data(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and remove PKCS padding
    decrypted_data = cipher.decrypt(data)
    return unpad(decrypted_data, 16)


def write_mode(key):
    old_content = b""
    now = datetime.now()
    dt_string = now.strftime("[%d/%m/%Y %H:%M:%S]")
    data = input("> Please input the data you want to write\n")
    data = f"{dt_string} > {data}\n".encode("utf-8")

    if len(data) == 0:
        print("Invalid data length")
        exit(-1)

    if not isfile(DIARY_PATH):
        iv = get_random_bytes(16)
    else:
        diary_file = open(DIARY_PATH, "rb+")
        iv = diary_file.read(16)
        old_content = diary_file.read()
        old_content = decrypt_data(old_content, key, iv)
        diary_file.close()

    with open(DIARY_PATH, "wb+") as diary:
        diary.write(iv)
        diary.write(encrypt_data(old_content + data, key, iv))


def read_mode(key):
    if not isfile(DIARY_PATH):
        print("There is no diary to read.")
        exit(-1)

    content = b""

    with open(DIARY_PATH, "rb") as diary_file:
        iv = diary_file.read(16)
        content = decrypt_data(diary_file.read(), key, iv)
    print("\n" + content.decode("utf-8"))
    return content


def get_bcrypt_key(key):
    salt = None
    if isfile(DIARY_SALT_PATH):
        with open(DIARY_SALT_PATH, "rb") as salt_file:
            salt = salt_file.read()
            if len(salt) != 16:
                print("Salt file is invalid")
                exit(-1)
    else:
        salt = get_random_bytes(16)
        with open(DIARY_SALT_PATH, "wb") as salt_file:
            salt_file.write(salt)

    b64pwd = b64encode(SHA256.new(key).digest())
    bcrypt_hash = SHA256.new(bcrypt(b64pwd, 14, salt)).digest()
    return bcrypt_hash


if __name__ == "__main__":
    key = getpass("> Please input the encryption key\n").encode("utf-8")
    mode = input("> Please input the usage mode\n").encode("utf-8")

    bcrypt_key = get_bcrypt_key(key)

    if mode == b"read":
        read_mode(bcrypt_key)
    elif mode == b"write":
        write_mode(bcrypt_key)
    else:
        print("Invalid usage mode")
        exit(-1)
