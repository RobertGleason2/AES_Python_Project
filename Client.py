#Robert Gleason and Jacob Sprouse

import socket
from Server import Socket
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

#create a socket object
connectionSocket = Socket.Server()

host = Socket.Host()

port = Socket.Port()

connection = True
key = get_random_bytes(16)
connectionSocket.connect((host, port))
while connection:

    message = input()

    messageBytes = message.encode()

    encryptCipher = AES.new(key, AES.MODE_ECB)

    decryptCipher = AES.new(key, AES.MODE_ECB)

    cipherText = encryptCipher.encrypt(pad(messageBytes, AES.block_size))
    print(cipherText)

    connectionSocket.send(key)

    connectionSocket.send(cipherText)

    # recieve
    recievedCipherText = connectionSocket.recv(1024)

    decryptedBytes = unpad(decryptCipher.decrypt(recievedCipherText),AES.block_size)

    recievedMessage = bytes.decode(decryptedBytes)

    print(f"The cipher text is {recievedCipherText} and the message is {recievedMessage}")

    print(recievedMessage)
    if recievedMessage == "Bye" or recievedMessage == "bye":
        connection = False
        connectionSocket.close()
