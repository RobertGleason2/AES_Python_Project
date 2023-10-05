# AES_Python_Project
SERVER ENCRYPTION: 
The server encryption uses 3 AES modes, ECB, CBC, and OFB. To run these you must download the files and run them in an IDE, I will update this to work on the command line so it is less of a hassle to show, but for now, the modes work fine and will encrypt or decrypt any of the three modes. The server also signs the 3 AES modes using RSA encryption

CLIENT ENCRYPTION:
The client uses the same 3 AES modes as the server and will send and receive messages from the server. The client will also create a private and public RSA key for signing the 3 modes.


PROJECT:
This project is to show cryptography encryption across a server and client. The private and public keys created by the project are for showing that it works by creating and using said key, it also is to show how the key is made from the server/client.


NOTE:
In an actual secure setting, the keys would not be shown; this is for demonstration purposes, so it is easier to understand where the RSA keys are created and pulled from.

THE FILES:
py files are the code that make a local client and server connection and encrypt messages through RSA and AES
