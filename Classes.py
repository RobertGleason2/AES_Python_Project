import socket
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


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

    @staticmethod
    def encryption_ecb(recieved_key, message):
        message_bytes = message.encode()
        encryptCipher = AES.new(recieved_key, AES.MODE_ECB)
        cipherText = encryptCipher.encrypt(pad(message_bytes, AES.block_size))
        return cipherText

    @staticmethod
    def decryption_ecb(recieved_key, recieved_cipher_text):
        decrypt_cipher = AES.new(recieved_key, AES.MODE_ECB)
        decrypted_bytes = unpad(decrypt_cipher.decrypt(recieved_cipher_text), AES.block_size)
        recieved_message = bytes.decode(decrypted_bytes)

        return recieved_message

    @staticmethod
    def encryption_cbc(received_key, message, iv):
        message_bytes = message.encode()
        encryption_cipher = AES.new(received_key, AES.MODE_CBC, iv)
        cipherText = encryption_cipher.encrypt(pad(message_bytes, AES.block_size))
        return cipherText

    @staticmethod
    def decryption_cbc(received_key, received_cipher_text, iv):
        decrypt_cipher = AES.new(received_key, AES.MODE_CBC, iv)
        decrypted_bytes = unpad(decrypt_cipher.decrypt(received_cipher_text), AES.block_size)
        recieved_message = bytes.decode(decrypted_bytes)

        return recieved_message
    @staticmethod
    def encryption_ofb(received_key, message, iv):
        message_bytes = message.encode()
        encryption_cipher = AES.new(received_key, AES.MODE_OFB, iv)
        cipher_text = encryption_cipher.encrypt(message_bytes)
        return cipher_text
    @staticmethod
    def decryption_ofb(received_key, received_cipher_text, iv):
        decrypt_cipher = AES.new(received_key, AES.MODE_OFB, iv)
        decrpted_bytes = decrypt_cipher.decrypt(received_cipher_text)
        received_message = bytes.decode(decrpted_bytes)
        return received_message

