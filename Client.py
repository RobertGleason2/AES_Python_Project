# Robert Gleason and Jacob Sprouse
# version 5

import socket
import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Classes import Socket, Cipher
# create a socket object
connectionSocket = Socket.Server()

host = Socket.Host()

port = Socket.Port()

connection = True

connectionSocket.connect((host, port))

cipher_mode = input("Input a mode my boi")

key_type = int(input("Input a key my boi \n"))

key = Cipher.cipher_key(key_type)

while connection:
    connectionSocket.send(cipher_mode.encode())
    message = input("Input a message my boi \n")
    iv = get_random_bytes(AES.block_size)
    match cipher_mode:
        case 'ECB':
            cipher_text = Cipher.encryption_ecb(key, message)

            print(cipher_text)

            connectionSocket.send(key)

            connectionSocket.send(cipher_text)

            # receive
            received_cipher_text = connectionSocket.recv(1024)

            received_message = Cipher.decryption_ecb(key, received_cipher_text)
        case 'CBC':
            cipher_text = Cipher.encryption_cbc(key, message, iv)
            print(f"Ciphertext {cipher_text}")

            connectionSocket.send(key)

            connectionSocket.send(cipher_text)
            time.sleep(0.2)
            connectionSocket.send(iv)
            print(f"IV {iv}")

            # receive
            received_cipher_text = connectionSocket.recv(1024)

            received_message = Cipher.decryption_ofb(key, received_cipher_text, iv)
        case 'OFB':
            cipher_text = Cipher.encryption_ofb(key, message, iv)
            print(f"Ciphertext {cipher_text}")

            connectionSocket.send(key)

            connectionSocket.send(cipher_text)
            time.sleep(0.2)
            connectionSocket.send(iv)
            print(f"IV {iv}")

            # receive
            received_cipher_text = connectionSocket.recv(1024)

            received_message = Cipher.decryption_ofb(key, received_cipher_text, iv)

    print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

    print(received_message)
    if received_message == "Bye" or received_message == "bye":
        connection = False
        connectionSocket.close()
