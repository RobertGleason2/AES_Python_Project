#Robert Gleason and Jacob Sprouse
import socket

#create a socket object
connectionSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

host = socket.gethostname()

port = 7777

connectionSocket.connect((host,port))
