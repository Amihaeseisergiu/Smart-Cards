from crypto import *

PubKM = None
PubKPG = None
PriKM = None
PubKC = None
PubKC_bytes = None
K = None
iv = b'\xc1\xa3\xd9\x8f\x93~4\xa8(\xdci/!\xf5\x80\xc4'
server_stopped_C = False
server_stopped_PG = False
connection_C = None
connection_PG = None

Amount = None
NC = None

with open("./public_key_M.pem", "rb") as key_file:
     PubKM = serialization.load_pem_public_key(key_file.read())
with open("./public_key_PG.pem", "rb") as key_file:
     PubKPG = serialization.load_pem_public_key(key_file.read())
with open("./private_key_M.pem", "rb") as key_file:
     PriKM = serialization.load_pem_private_key(key_file.read(), password=None)

def handle_read_C():
    global server_stopped_C
    global connection_C
    global connection_PG
    global PubKC
    global PriKM
    global PubKC_bytes
    global PubKPG
    global K
    global iv
    global Amount
    global NC
    
    while not server_stopped_C:
        try:
            data = connection_C.recv(1000000)
            splitted = data.decode().split("@@@")
            
            if splitted[0] == "PubKC":
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKM, cryptedK)
                PubKC_bytes = decrypt_AES(decryptedK, iv, m)
                PubKC = serialization.load_pem_public_key(PubKC_bytes)
                print("[1] Received PubKC")
                
                sid = str(random.randint(0,9))
                SigM = sign_RSA(PriKM, sid.encode())
                plaintext = sid + "@@@" + str(SigM)
                
                print("[2] Sending sid and its signature")
                m = encrypt_AES(decryptedK, iv, plaintext.encode())
                cryptedK = encrypt_RSA(PubKC, decryptedK)
                
                plaintext = "Sid" + "@@@" + str(m) + "@@@" + str(cryptedK)
                connection_C.sendall(plaintext.encode())
            elif splitted[0] == "PMPO":
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKM, cryptedK)
                
                print("[3] Received Payment message and Purchase order")
                PMPO = decrypt_AES(decryptedK, iv, m)
                PO = PMPO.decode().split("@@@", 2)[2]
                splitted_PO = PO.split("@@@")
                s = "@@@"
                to_verify = splitted_PO[0] + s + splitted_PO[1] + s +splitted_PO[2] + s + splitted_PO[3]
                signature = splitted_PO[4][2:-1].encode().decode('unicode_escape').encode('latin-1')
                
                if verify_RSA(PubKC, signature, to_verify.encode()):
                    print("[4] Purchase order signature matches")
                    
                    PM = PMPO.decode().rsplit("@@@", 5)[0]
                    Sid = splitted_PO[1]
                    Amount = splitted_PO[2]
                    NC = splitted_PO[3]
                    to_sign = Sid + s + str(PubKC_bytes) + s + Amount
                    signature = sign_RSA(PriKM, to_sign.encode())
                    
                    PM_and_signature = PM + s + str(signature)
                    m = encrypt_AES(K, iv, PM_and_signature.encode())
                    cryptedK = encrypt_RSA(PubKPG, K)
                    
                    print("[5] Redirecting PM and signature of Sid,PubKC,Amount to PG")
                    plaintext = "PMandSignature" + "@@@" + str(m) + "@@@" + str(cryptedK)
                    connection_PG.sendall(plaintext.encode())
                else:
                    print("[4] Purchase order signature doesn't match. Aborting...")
                    server_stopped_C = True
                    break
        except:
            server_stopped_C = True
            break
        
def handle_write_C():
    global server_stopped_C
    global connection_C
    
    while not server_stopped_C:
        try:
            message = input()
            connection_C.sendall(message.encode())
        except:
            server_stopped_C = True
            break

def server_program():
    global connection_C
    global server_stopped_C

    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    connection_C, address = server_socket.accept()
    print("C connected")
    
    threading.Thread(target=handle_read_C, args=(), daemon=True).start()
    threading.Thread(target=handle_write_C, args=(), daemon=True).start()
    while not server_stopped_C:
        pass

    connection_C.close()
    
    print("Client left. Restarting server...")
    server_stopped_C = False
    server_socket.close()
    server_program()

def handle_read_PG():
    global server_stopped_PG
    global connection_PG
    global connection_C
    global K
    global PubKC
    global PubKPG
    global Amount
    global NC
    
    while not server_stopped_PG:
        try:
            data = connection_PG.recv(1000000)
            splitted = data.decode().split("@@@")
            
            if splitted[0] == "RespandSignature":
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKM, cryptedK)
                
                print("[6] Received Resp, Sid and signature")
                Resp_and_signature = decrypt_AES(decryptedK, iv, m)
                Resp_splitted = Resp_and_signature.decode().split("@@@")
                Resp = Resp_splitted[0]
                Sid = Resp_splitted[1]
                s = "@@@"
                
                to_verify = Resp + s + Sid + s + Amount + s + NC
                signature = Resp_splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                
                if verify_RSA(PubKPG, signature, to_verify.encode()):
                    print("[7] Signature of Resp, Sid, Amount, NC matches")
                
                    m = encrypt_AES(K, iv, Resp_and_signature)
                    cryptedK = encrypt_RSA(PubKC, K)
                    
                    print("[8] Redirecting Resp, Sid and signature to C")
                    plaintext = "RespandSignature" + "@@@" + str(m) + "@@@" + str(cryptedK)
                    connection_C.sendall(plaintext.encode())
                else:
                    print("[7] Signature of Resp, Sid, Amount, NC doesn't match. Aborting...")
                    server_stopped_PG = True
                    break
        except:
            server_stopped_PG = True
            break

def handle_write_PG():
    global server_stopped_PG
    global connection_PG
    
    while not server_stopped_PG:
        try:
            message = input()
            connection_PG.sendall(message.encode())
        except:
            server_stopped_PG = True
            break

def client_program():
    global connection_PG
    global server_stopped_PG
    global K

    host = socket.gethostname()
    port = 5001

    accepted = False
    connection_PG = socket.socket()
    
    while not accepted:
        try:
            connection_PG.connect((host, port))
            accepted = True
            print("Connected to PG")
        except:
            print("Waiting for PG to open...")
    
    K = os.urandom(32)
    print("---Generated AES session key---")

    threading.Thread(target=handle_read_PG, args=(), daemon=True).start()
    threading.Thread(target=handle_write_PG, args=(), daemon=True).start()
    while not server_stopped_PG:
        pass

    connection_PG.close()
    
    server_stopped_PG = False
    print("Server closed")
    client_program()

sv = threading.Thread(target=server_program, args=())
cl = threading.Thread(target=client_program, args=())
sv.start()
cl.start()
sv.join()
cl.join()