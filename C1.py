import socket
import threading, time, binascii
from hashlib import sha256
import rsa

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
my_portID = 5551

my_addr = ('localhost', my_portID) 
CA_addr = ('localhost', CA_portID)


# print(rsa_key_pair_generate(1801669, 4293071))
#add this function later implementing RSA
privateK = (3790638075029, 7734692935499)
publicK = (7548004284869, 7734692935499)

CA_publicK = (1026816288691, 7734692935499)

CA_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CA_sock.connect(CA_addr)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#getting my cert from CA
print("Requesting my Certificate from CA...\n")
msg = "RequestCertificate:" + "Harshit"
CA_sock.send(msg.encode())

recv = CA_sock.recv(4096)

#add this function later implementing RSA
certificate = rsa.rsa_decypt(recv, CA_publicK).decode("utf-8")

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

o = input("Enter Y to Ask for your certificate: ")
if o.lower()=="y":
    print("Requesting other Client's Certificate from CA...\n")
    msg = "RequestCertificate:" + "Soumya"
   
    CA_sock.send(msg.encode())
    
    recv = CA_sock.recv(4096)
    while len(recv) == 0:
        print("failed to connect")
        CA_sock.close()
        CA_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        CA_sock.connect(CA_addr)
        CA_sock.send(msg.encode())
        recv = CA_sock.recv(4096)
    #add this function later implementing RSA
    client_certificate = rsa.rsa_decypt(recv, CA_publicK).decode("utf-8")

    print("\nReceived Certificate of other Client (Soumya) from CA: ", client_certificate, "\n")
    print("Client ID:", certificate.split("|")[0])
    print("Client Public Key:", certificate.split("|")[1])
    print("Time of Issue:", certificate.split("|")[2])
    print("Duration of Certificate:", certificate.split("|")[3], " mins")
    print("ID of CA:", certificate.split("|")[4])
    print()

    client_duration = int(client_certificate.split("|")[3])
    client_publicK = client_certificate.split("|")[1]
    client_publicK = (int(client_publicK.split(",")[0]), int(client_publicK.split(",")[1]))
    client_port = int(client_certificate.split("|")[0])
    print(client_duration)
    print(client_publicK)
    print(client_port)
    # print(client_duration)
    #deleteing the client certificate agar duration of it has expired
    thread = threading.Thread(target=clientCert_validity, args=(client_duration,))
    thread.start()
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#Sending and receiving to client 

while True:
    if o.lower()!="y":
        print("You don't have a certificate to communicate with other client!\n")
        break

    msg = input("Enter Message to send to client or (Q) to Exit: ")
    if msg.lower() =="q":
        break
    if (client_certificate!="" and verification(client_certificate)):

        #add this function later implementing RSA
        msg = "Message:" + msg
        msg_e = msg.encode("utf-8")
        msg_e = rsa.rsa_encypt(msg_e, privateK)
        msg_e = rsa.rsa_encypt(msg_e, client_publicK)

        client_addr = ('localhost', client_port)
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(client_addr)
       
        client_sock.send(msg_e)        
    else:
        print("Client Certificate Expired or Invalid!\n")
        break
 
    recv = client_sock.recv(4096)
    client_sock.close()
    msg = rsa.rsa_decypt(recv, client_publicK)
    msg = rsa.rsa_decypt(msg,privateK).decode()

    if msg.startswith("Reply:"):
        msg = msg.split(":")[1]
        print("Reply from client:", msg)
    else:
        print("\nERROR: ", recv)

CA_sock.close()