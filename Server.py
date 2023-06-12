#Robert Gleason and Jacob Sprouse
import socket

#create a socket object that will listen
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#get the local machine name
host = socket.gethostname()
#this is the port that the socket will listen on 
port = 7777
#bind the socket to the port, making a bridge
serverSocket.bind((host,port))
#start listening 
serverSocket.listen()

print("Waiting for connection.....")
# addr_port is a tuple that contains both the address and the port number
#clientScoket is the communication variable between the host and port
clientSocket, addr_port = serverSocket.accept()

print("\nGot a connection from " + str(addr_port))