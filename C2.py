import socket
import threading, time, rsa, binascii
from hashlib import sha256

#Example Certificate: 5551|7548004284869,7734692935499|2024-07-03 16:21:12.357246|15|5550|<sha256 value iss se pehle ka stuff>
def myCert_validity(duration):
    global certificate
    time.sleep(duration*60)
    certificate = ""

def clientCert_validity(client_duration):
    global client_certificate
    time.sleep(client_duration*60)
    client_certificate = ""

def verification(cert):

    decrypted_parts = cert.split('|')
    certificate_content = '|'.join(decrypted_parts[:-1])
    received_hash = decrypted_parts[-1]
    received_hash = rsa.rsa_decypt(binascii.unhexlify(received_hash),CA_publicK)
    calculated_hash = sha256(certificate_content.encode("utf-8")).digest()
    return received_hash == calculated_hash

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CA_portID = 5550
my_portID = 5552
my_addr = ('localhost', my_portID) 
CA_addr = ('localhost', CA_portID)


# using rsa_key_generate_pair(1801669, 4293071)
#add this function later implementing RSA
privateK = (5644341809299, 7734692935499)
publicK = (67774058299, 7734692935499)

CA_publicK = (1026816288691, 7734692935499)

CA_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CA_sock.connect(CA_addr)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#getting my cert from CA
print("Requesting my Certificate from CA...\n")
msg = "RequestCertificate:" + "Soumya"
CA_sock.send(msg.encode())

recv = CA_sock.recv(4096)

#add this function later implementing RSA
certificate = rsa.rsa_decypt(recv, CA_publicK).decode("'utf-8")

print("\nReceived Certificate from CA: ", certificate, "\n")
print("My ID:", certificate.split("|")[0])
print("My Public Key:", certificate.split("|")[1])
print("Time of Issue:", certificate.split("|")[2])
print("Duration of Certificate:", certificate.split("|")[3], " mins")
print("ID of CA:", certificate.split("|")[4])
print()

duration = int(certificate.split("|")[3])


#deleteing the certificate agar duration of it has expired
thread = threading.Thread(target=myCert_validity, args=(duration,))
thread.start()


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#getting other client's certificate from CA
o2 = input("Enter Y to Ask for other client's certificate: ")
if o2.lower()=="y":
    print("Requesting other Client's Certificate from CA...\n")
    msg = "RequestCertificate:" + "Harshit"
    CA_sock.send(msg.encode())

    recv = CA_sock.recv(4096)
    # recv = CA_sock.recv(4096)
    while len(recv) == 0:
        print("failed to connect")
        CA_sock.close()
        CA_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CA_sock.connect(CA_addr)
        CA_sock.send(msg.encode())
        recv = CA_sock.recv(4096)

    #add this function later implementing RSA
    client_certificate = rsa.rsa_decypt(recv, CA_publicK).decode('utf-8')

    print("\nReceived Certificate of other Client (Harshit) from CA: ", client_certificate, "\n")
    print("Client ID:", client_certificate.split("|")[0])
    print("Client Public Key:", client_certificate.split("|")[1])
    print("Time of Issue:", client_certificate.split("|")[2])
    print("Duration of Certificate:", client_certificate.split("|")[3], " mins")
    print("ID of CA:", client_certificate.split("|")[4])
    print()

    client_duration = int(client_certificate.split("|")[3])
    client_publicK = client_certificate.split("|")[1]
    client_publicK = (int(client_publicK.split(",")[0]), int(client_publicK.split(",")[1]))
    client_port = int(client_certificate.split("|")[0])

    #deleteing the client certificate agar duration of it has expired
    thread = threading.Thread(target=clientCert_validity, args=(client_duration,))
    thread.start()
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def reply_client(client_sock, address):
    # while True:
        data = client_sock.recv(4096)
        data = rsa.rsa_decypt(data,  client_publicK )
        data = rsa.rsa_decypt(data, privateK)
        data = data.decode()
        if (data.startswith("Message:")):
            if (client_certificate!="" and verification(client_certificate)):
                msg = data.split(":")[1]
                print(f"Received a message from client ({address}): ", msg)
                reply = input("Enter your reply: ")
                reply = "Reply:"+reply
                reply = reply.encode("utf-8")
                reply = rsa.rsa_encypt(reply, privateK)
                reply = rsa.rsa_encypt(reply, client_publicK)

                client_sock.send(reply)
            else:
                print("Client Certificate Expired or Invalid!\n")
        
        else:
            print(f"Client at {address} says: ", data)
            print()


#Receiving from client(s) 
my_sock =  socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
my_sock.bind(my_addr)

my_sock.listen(5)
while True:
    client_sock, address = my_sock.accept()
    client_sock.settimeout(60)
    threading.Thread(target=reply_client, args=(client_sock, address)).start()
