import socket
import threading, datetime, rsa
from hashlib import sha256
import binascii

#Example Certificate: 5551|7548004284869,7734692935499|2024-07-03 16:21:12.357246|15|5550|<sha256 value iss se pehle ka stuff>

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

my_portID = 5550
my_addr = ('localhost', my_portID) 
clients_pubK = {"Harshit": (7548004284869, 7734692935499), "Soumya": (67774058299, 7734692935499)}
clients_addr = {"Harshit": 5551, "Soumya": 5552}

# using rsa_key_pair_generate(1801669, 4293071)
#add this function later implementing RSA
privateK =  (1780809042091, 7734692935499)
publicK = (1026816288691, 7734692935499)

my_sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
my_sock.bind(my_addr)

my_sock.listen(5)

print("Certification Authority is now listening for requests...\n")
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def reply_client(client_sock: socket.socket, address):
    
    print(f"\nClient at {address} has connected\n")
    while True:
        try:
            data = client_sock.recv(4096).decode()
        except TimeoutError as e:
            print("conection timed out")
            client_sock.close()
            break

        if (data.startswith("RequestCertificate:")):
            
            data = data.split(":")[1]
            client_ID = clients_addr[data]
            client_key = clients_pubK[data]

            certificate = str(client_ID) +"|"+ str(client_key[0])+","+str(client_key[1]) +"|"+ str(datetime.datetime.now())

            dur = input("\nEnter validity duration for certificate (in mins): ")

            certificate += "|" + dur + "|" + str(my_portID)

            hash_bytes = sha256(certificate.encode("utf-8")).digest()
            encrypted_hash = rsa.rsa_encypt(hash_bytes, privateK)
            certificate += "|" + binascii.hexlify(encrypted_hash).decode("utf-8")
            encrypted_certificate = rsa.rsa_encypt(certificate.encode("utf-8"), privateK)

            print("\nReplying to Client:", encrypted_certificate)
            client_sock.send(encrypted_certificate)

        else:
            print("ERROR")
            break

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#Receiving from client(s) 
    
while True:
    client_sock, address = my_sock.accept()
    client_sock.settimeout(20)
    threading.Thread(target=reply_client, args=(client_sock, address) ).start()


