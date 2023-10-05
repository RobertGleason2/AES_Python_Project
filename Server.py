# Robert Gleason and Jacob Sprouse
# version 7
import time
from Classes import Socket, Cipher
from Crypto.PublicKey import RSA

if __name__ == "__main__":
    serverSocket = Socket.Server()
    host = Socket.Host()
    name = "server"
    port = Socket.Port()

    # bind the socket to the port, making a bridge
    serverSocket.bind((host, port))
    # start listening
    serverSocket.listen()

    print("Waiting for connection.....")
    # addr_port is a tuple that contains both the address and the port number
    # clientScoket is the communication variable between the host and port
    clientSocket, addr_port = serverSocket.accept()

    """ Creates RSA key for server"""
    rsa_key = Cipher.generate_rsa_key()
    rsa_private = Cipher.generate_privk(rsa_key, 'server_private.pem')
    rsa_public = Cipher.generate_pk(rsa_key, 'server_public.pem')

    """Reads the key from the generated files and exports the key"""
    rsa_server_public_key_data = RSA.import_key(open("server_public.pem").read()).export_key()
    rsa_server_private_key_data = RSA.import_key(open("server_private.pem").read()).export_key()

    """imports the data of the server's private key from the exported data"""
    rsa_server_private_key = RSA.import_key(rsa_server_private_key_data)

    """sends the public key data to the client """
    clientSocket.send(rsa_server_public_key_data)

    print("\nGot a connection from " + str(addr_port))
    while True:
        client_public_key_data = clientSocket.recv(2048)
        client_public_key = RSA.import_key(client_public_key_data)
        # print(f"Key client{client_public_key}") Debugging purposes

        received_cipher_mode = clientSocket.recv(1024)
        received_aes_key = clientSocket.recv(1024)
        received_cipher_text = clientSocket.recv(1024)

        decrypted_aes_key = Cipher.decrypt_rsa(rsa_server_private_key, received_aes_key)
        print(f"RSA {received_aes_key}")
        # print(received_cipher_text)
        match received_cipher_mode.decode():
            case "ECB":
                # NOTE: ECB is not secure at all, this is just for learning purposes.
                # Decrypts the received message and prints it to the screen
                received_message = Cipher.decryption_ecb(decrypted_aes_key, received_cipher_text)
                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Gets input from the server user, encrypts the message and key and sends them to the client
                message = input("Input a message \n")
                encrypted_aes_key = Cipher.encrypt_rsa(client_public_key, decrypted_aes_key)
                cipher_text = Cipher.encryption_ecb(encrypted_aes_key, message, name)
                print(cipher_text)
                clientSocket.send(cipher_text)
                clientSocket.send(encrypted_aes_key)
                # If message received is Bye or bye, ends the connection
                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()

            case "CBC":
                # Decrypts the received message and prints it to the screen
                print(f"Ciphertext {received_cipher_text}")
                received_iv = clientSocket.recv(1024)
                # print(f"IV: {received_iv}") debugging purpose
                # print(f"AES Key: {decrypted_aes_key}") debugging purpose
                received_message = Cipher.decryption_cbc(decrypted_aes_key, received_cipher_text, received_iv)
                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Gets input from the server user, encrypts the message and key and sends them and IV to the client
                message = input("Input a message my boi \n")
                encrypted_aes_key = Cipher.encrypt_rsa(client_public_key, decrypted_aes_key)
                cipher_text = Cipher.encryption_cbc(encrypted_aes_key, message, received_iv, name)
                print(cipher_text)
                clientSocket.send(cipher_text)
                clientSocket.send(encrypted_aes_key)
                # If message received is Bye or bye, ends the connection
                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()
            case "OFB":
                # Decrypts the received message and prints it to the screen
                print(f"Ciphertext {received_cipher_text}")
                received_iv = clientSocket.recv(1024)
                print(received_iv)
                received_message = Cipher.decryption_ofb(decrypted_aes_key, received_cipher_text, received_iv)
                print(f"The cipher text is {received_cipher_text} and the message is {received_message}")

                # Gets input from the server user, encrypts the message and key and sends them and IV to the client
                message = input("Input a message my boi \n")
                encrypted_aes_key = Cipher.encrypt_rsa(client_public_key, decrypted_aes_key)
                cipher_text = Cipher.encryption_ofb(encrypted_aes_key, message, received_iv, name)
                print(cipher_text)
                clientSocket.send(cipher_text)
                clientSocket.send(encrypted_aes_key)
                # If message received is Bye or bye, ends the connection
                if received_message == "Bye" or received_message == "bye":
                    clientSocket.close()
                    print("Back to listening...")
                    serverSocket.listen()
                    clientSocket, addr_port = serverSocket.accept()

