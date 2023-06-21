#Robert Gleason and Jacob Sprouse
import socket

#create a socket object
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 7777

connection = True
while connection:
    connectionSocket.connect((host, port))

    message = "Hello"

    messageBytes = message.encode()

    connectionSocket.send(messageBytes)

    #recieve
    recievedBytes = connectionSocket.recv(1024)

    recievedMessage = bytes.decode(recievedBytes)

    print(recievedMessage)

    connection == False

connectionSocket.close()
