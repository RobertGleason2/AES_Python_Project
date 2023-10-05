# Robert Gleason and Jacob Sprouse
# version 7

import socket
from Cryptodome.Cipher import AES
from Crypto.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP


class Socket(object):

    @staticmethod
    def Server():
        # create a socket object that will listen
        hostServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return hostServerSocket

    @staticmethod
    def Host():
        # get the local machine name
        serverHost = socket.gethostname()
        return serverHost

    @staticmethod
    def Port():
        # this is the port that the socket will listen on
        serverPort = 7777
        return serverPort


class Cipher(object):
    @staticmethod
    def cipher_key(key):
        keyval = key // 8
        cipher_key = get_random_bytes(keyval)
        return cipher_key

    """ Gets the RSA key information for encryption and generates the AES key.
    Generates AES ECB mode encrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def encryption_ecb(received_key, message, user):
        try:
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("server_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == "server":
                rsa_key_data = RSA.import_key(open("client_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Value Error")
        except ValueError as ve:
            print("Error", ve)

        cipher_key = Cipher.decrypt_rsa(rsa_key, received_key)
        message_bytes = message.encode()
        encryptCipher = AES.new(cipher_key, AES.MODE_ECB)
        cipherText = encryptCipher.encrypt(pad(message_bytes, AES.block_size))
        return cipherText

    """Generates AES ECB mode decrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def decryption_ecb(received_key, received_cipher_text):
        decrypt_cipher = AES.new(received_key, AES.MODE_ECB)
        decrypted_bytes = unpad(decrypt_cipher.decrypt(received_cipher_text), AES.block_size)
        received_message = bytes.decode(decrypted_bytes)

        return received_message

    """ Gets the RSA key information for encryption and generates the AES key.
    Generates AES CBC mode encrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def encryption_cbc(received_key, message, iv, user):
        try:
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("server_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == "server":
                rsa_key_data = RSA.import_key(open("client_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Value Error")
        except ValueError as ve:
            print("Error", ve)

        cipher_key = Cipher.decrypt_rsa(rsa_key, received_key)
        message_bytes = message.encode()
        encryption_cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
        cipherText = encryption_cipher.encrypt(pad(message_bytes, AES.block_size))
        return cipherText

    """Generates AES CBC mode decrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def decryption_cbc(received_key, received_cipher_text, iv):
        decrypt_cipher = AES.new(received_key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(decrypt_cipher.decrypt(received_cipher_text), AES.block_size)
        received_message = bytes.decode(decrypted_bytes)

        return received_message

    """ Gets the RSA key information for encryption and generates the AES key.
    Generates AES OFB mode encrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def encryption_ofb(received_key, message, iv, user):
        try:
            # user variable is hard coded for now. This allows us to check the which public/private keys we need
            if user.lower() == 'client':
                rsa_key_data = RSA.import_key(open("server_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            elif user.lower() == "server":
                rsa_key_data = RSA.import_key(open("client_private.pem").read()).export_key()
                rsa_key = RSA.import_key(rsa_key_data)
            else:
                raise ValueError("Value Error")
        except ValueError as ve:
            print("Error", ve)

        cipher_key = Cipher.decrypt_rsa(rsa_key, received_key)
        message_bytes = message.encode()
        encryption_cipher = AES.new(cipher_key, AES.MODE_OFB, iv)
        cipher_text = encryption_cipher.encrypt(message_bytes)
        return cipher_text

    """Generates AES OFB mode decrypt cipher and decrypts the ciphertext passed."""
    @staticmethod
    def decryption_ofb(received_key, received_cipher_text, iv):
        decrypt_cipher = AES.new(received_key, AES.MODE_OFB, iv)
        decrypted_bytes = decrypt_cipher.decrypt(received_cipher_text)
        received_message = bytes.decode(decrypted_bytes)
        return received_message

    """Generates the RSA key."""
    @staticmethod
    def generate_rsa_key():
        key = RSA.generate(2048)
        return key

    """Generates the RSA private key. """
    @staticmethod
    def generate_privk(key, filename):
        private_key = key.export_key()
        file_out = open(filename, 'wb')
        file_out.write(private_key)
        file_out.close()
        return private_key

    """Generates the RSA public key. """
    @staticmethod
    def generate_pk(key, filename):
        public_key = key.publickey().export_key()
        file_out = open(filename, 'wb')
        file_out.write(public_key)
        file_out.close()
        return public_key

    """Creates an RSA cipher using the private key passed and encrypts the AES key using RSA cipher."""
    @staticmethod
    def encrypt_rsa(private_key, aes_key):
        rsa_cipher = PKCS1_OAEP.new(private_key)
        encrypt_rsa_key = rsa_cipher.encrypt(aes_key)
        return encrypt_rsa_key

    """Creates an RSA cipher using the public key passed and decrypts the AES key using RSA cipher."""
    @staticmethod
    def decrypt_rsa(public_key, encrypted_rsa_key):
        rsa_cipher = PKCS1_OAEP.new(public_key)
        decrypt_rsa_key = rsa_cipher.decrypt(encrypted_rsa_key)
        return decrypt_rsa_key
