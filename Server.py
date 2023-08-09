# Robert Gleason and Jacob Sprouse
# version 5

from Classes import Socket, Cipher

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

                print(f"Ciphertext {received_cipher_text}")
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
            case "OFB":

                print(f"Ciphertext {received_cipher_text}")
                received_iv = clientSocket.recv(1024)

                print(received_iv)

                received_message = Cipher.decryption_ofb(received_key, received_cipher_text, received_iv)

                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Response
                message = input()

                cipher_text = Cipher.encryption_ofb(received_key, message, received_iv)

                print(cipher_text)

                clientSocket.send(cipher_text)
                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()


