# Robert Gleason and Jacob Sprouse
# version 6

import socket
import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Crypto.PublicKey import RSA

import Classes
from Classes import Socket, Cipher
# create a socket object
connectionSocket = Socket.Server()

host = Socket.Host()

port = Socket.Port()

connection = True

connectionSocket.connect((host, port))

cipher_mode = input("Input a mode my boi \n")

key_type = int(input("Input a key my boi \n"))

aes_key = Cipher.cipher_key(key_type)

name = input("Input the user: \n")

# rsa_key = Cipher.generate_sk()
rsa_key = Cipher.generate_rsa_key()
rsa_private_key_generate = Cipher.generate_privk(rsa_key, 'client_private.pem')
rsa_public_key_generate = Cipher.generate_pk(rsa_key, 'client_public.pem')

"""Read the private key variable"""
rsa_client_private_key_data = RSA.import_key(open("client_private.pem").read()).export_key()
rsa_client_private_key = RSA.import_key(rsa_client_private_key_data)

"""Read the public key into a varaible variable """
rsa_client_public_key_data = RSA.import_key(open("client_public.pem").read()).export_key()

while connection:
    """Send the client public key to the server for encryption"""
    connectionSocket.send(rsa_client_public_key_data)
    connectionSocket.send(cipher_mode.encode())
    message = input("Input a message my boi \n")
    iv = get_random_bytes(AES.block_size)

    """receive the servers public key for client encryption"""
    rsa_server_public_key_data = connectionSocket.recv(2048)
    rsa_server_public_key = RSA.import_key(rsa_server_public_key_data)  # import the key from data
    print(rsa_server_public_key)  # debugging
    match cipher_mode:
        case 'ECB':
            encrypted_aes_key = Cipher.encrypt_rsa(rsa_server_public_key, aes_key)
            cipher_text = Cipher.encryption_ecb(encrypted_aes_key, message, name)

            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(cipher_text)

            # receive
            received_cipher_text = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)
            decrypted_rsa_key = Cipher.decrypt_rsa(rsa_client_private_key, received_server_key)
            received_message = Cipher.decryption_ecb(decrypted_rsa_key, received_cipher_text)
        case 'CBC':
            encrypted_aes_key = Cipher.encrypt_rsa(rsa_server_public_key, aes_key)
            cipher_text = Cipher.encryption_cbc(encrypted_aes_key, message, iv, name)
            print(f"{encrypted_aes_key}")
            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(cipher_text)
            time.sleep(0.2)
            connectionSocket.send(iv)

            print(f"Ciphertext {cipher_text}")
            print(f"IV {iv}")

            # receive
            received_cipher_text = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)
            decrypted_rsa_key = Cipher.decrypt_rsa(rsa_client_private_key, received_server_key)
            received_message = Cipher.decryption_cbc(decrypted_rsa_key, received_cipher_text, iv)
        case 'OFB':
            encrypted_aes_key = Cipher.encrypt_rsa(rsa_server_public_key, aes_key)
            cipher_text = Cipher.encryption_ofb(encrypted_aes_key, message, iv, name)

            connectionSocket.send(encrypted_aes_key)
            connectionSocket.send(cipher_text)

            time.sleep(0.2)
            connectionSocket.send(iv)
            print(f"IV {iv}")

            # receive
            received_cipher_text = connectionSocket.recv(1024)
            received_server_key = connectionSocket.recv(2048)
            decrypted_rsa_key = Cipher.decrypt_rsa(rsa_client_private_key, received_server_key)
            received_message = Cipher.decryption_ofb(decrypted_rsa_key, received_cipher_text, iv)

    print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

    print(received_message)
    if received_message == "Bye" or received_message == "bye":
        connection = False
        connectionSocket.close()
