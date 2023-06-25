#Robert Gleason and Jacob Sprouse
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


if __name__== "__main__":
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
        recievedKey = clientSocket.recv(1024)

        recievedCipherText = clientSocket.recv(1024)

        decryptCipher = AES.new(recievedKey, AES.MODE_ECB)
        encryptCipher = AES.new(recievedKey, AES.MODE_ECB)

        decryptedBytes = unpad(decryptCipher.decrypt(recievedCipherText), AES.block_size)

        recievedMessage = bytes.decode(decryptedBytes)

        print(f"The cipher text is {recievedCipherText} and the message is {recievedMessage}" )

        # Response
        message = input()

        messageBytes = message.encode()

        cipherText = encryptCipher.encrypt(pad(messageBytes,AES.block_size))

        print(cipherText)

        clientSocket.send(cipherText)

        if recievedMessage == "Bye" or recievedMessage == "bye":
            clientSocket.close()
            print("Back to listening...")
            serverSocket.listen()
            clientSocket, addr_port = serverSocket.accept()

