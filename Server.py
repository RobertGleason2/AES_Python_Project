# Robert Gleason and Jacob Sprouse
# version 4
import socket
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import time


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


if __name__ == "__main__":
    serverSocket = Socket.Server()

    host = Socket.Host()

    port = Socket.Port()

    # bind the socket to the port, making a bridge
    serverSocket.bind((host, port))
    # start listening
    serverSocket.listen()

    print("Waiting for connection.....")
    # addr_port is a tuple that contains both the address and the port number
    # clientScoket is the communication variable between the host and port
    clientSocket, addr_port = serverSocket.accept()

    print("\nGot a connection from " + str(addr_port))
    while True:
        received_cipher_mode = clientSocket.recv(1024)

        print(received_cipher_mode)

        received_key = clientSocket.recv(1024)

        received_cipher_text = clientSocket.recv(1024)
        time.sleep(2)
        # print(received_cipher_text)
        match received_cipher_mode.decode():
            case "ECB":

                received_message = Cipher.decryption_ecb(received_key, received_cipher_text)

                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Response
                message = input()

                cipher_text = Cipher.encryption_ecb(received_key, message)

                print(cipher_text)

                clientSocket.send(cipher_text)

                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()

            case "CBC":
                """CBC currently doesn't work properly as the socket receiving the data is being overloaded"""
                print(f"Ciphertext{received_cipher_text}")
                received_iv = clientSocket.recv(1024)
                print(received_iv)

                received_message = Cipher.decryption_cbc(received_key, received_cipher_text, received_iv)

                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Response
                message = input()

                cipher_text = Cipher.encryption_cbc(received_key, message, received_iv)

                print(cipher_text)

                clientSocket.send(cipher_text)
                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()


