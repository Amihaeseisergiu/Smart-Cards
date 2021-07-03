from crypto import *

PubKM = None
PubKPG = None
PubKC = None
PriKC = None
K = None
iv = b'\xc1\xa3\xd9\x8f\x93~4\xa8(\xdci/!\xf5\x80\xc4'
server_stopped = False
connection = None

Sid = None
Amount = None
NC = None
start_exchange = None

with open("./public_key_M.pem", "rb") as key_file:
     PubKM = serialization.load_pem_public_key(key_file.read())
with open("./public_key_PG.pem", "rb") as key_file:
     PubKPG = serialization.load_pem_public_key(key_file.read())

def handle_read():
    global server_stopped
    global connection
    global PubKC
    global PubKPG
    global PriKC
    global iv
    global Amount
    global NC
    global start_exchange
    
    while not server_stopped:
        try:
            data = connection.recv(1000000)
            splitted = data.decode().split("@@@")
            
            if splitted[0] == "Sid":
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKC, cryptedK)
                pt = decrypt_AES(decryptedK, iv, m).decode()
                
                print("[2] Received Sid and its signature")
                result = pt.split("@@@")
                SigM = result[1][2:-1]
                if verify_RSA(PubKM, SigM.encode().decode('unicode_escape').encode('latin-1'), result[0].encode()):
                    global Sid
                    Sid = result[0]
                    print("[3] Signature matches")
                    print("---Setup done---")
                else:
                    print("[3] Signature doesn't match. Aborting...")
                    server_stopped = True
                    break
            elif splitted[0] == "RespandSignature":
                end = time.time()
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKC, cryptedK)
                
                Resp_and_signature = decrypt_AES(decryptedK, iv, m).decode() 
                print("[2] Received Resp, Sid and signature")

                Resp_and_Sid = Resp_and_signature.rsplit("@@@", 1)[0]
                s = "@@@"
                to_verify = Resp_and_Sid + s + Amount + s + NC
                signature = Resp_and_signature.rsplit("@@@", 1)[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                
                if end - start_exchange < 5:
                    if verify_RSA(PubKPG, signature, to_verify.encode()):
                        print("[3] Signature of Resp, Sid, Amount, NC matches")
                        print("---Exchange done---")
                    else:
                        print("[3] Signature of Resp, Sid, Amount, NC doesn't match")
                        server_stopped = True
                        break
                else:
                    print("---Time expired---")
                    server_stopped = True
                    break
        except:
            server_stopped = True
            break

def handle_write():
    global server_stopped
    global connection
    global PubKC
    global PubKPG
    global PriKC
    global K
    global iv
    global Amount
    global NC
    global Sid
    global start_exchange
    
    while not server_stopped:
        try:
            message = input()
            
            if message == "setup":
                print("[1] Sending encrypted PubKC")
                m = encrypt_AES(K, iv, get_public_bytes(PubKC))
                cryptedK = encrypt_RSA(PubKM, K)
                
                plaintext = "PubKC" + "@@@" + str(m) + "@@@" + str(cryptedK)
                connection.sendall(plaintext.encode())
            elif message == "exchange":
                Amount = str(random.randint(500,600))
                NC = str(random.getrandbits(128))
                CardN = str(random.randint(100,200))
                CardExp = "11.01.2022"
                CCode = "sm45wm"
                M = str(random.randint(100,200))
                s = "@@@"
                
                PI = CardN + s + CardExp + s + CCode + s + Sid + s + Amount + s + str(get_public_bytes(PubKC)) + s + NC + s + M
                signed_PI = sign_RSA(PriKC, PI.encode())
                
                PM = PI + s + str(signed_PI)
                crypted_PM = encrypt_AES(K, iv, PM.encode())
                crypted_K_PM = encrypt_RSA(PubKPG, K)
                PM = str(crypted_PM) + s + str(crypted_K_PM)
                
                OrderDesc = "transaction"
                to_sign_PO = OrderDesc + s + Sid + s + Amount + s + NC
                signed_PO = sign_RSA(PriKC, to_sign_PO.encode())
                PO = to_sign_PO + s + str(signed_PO)
                
                message = PM + s + PO
                m = encrypt_AES(K, iv, message.encode())
                cryptedK = encrypt_RSA(PubKM, K)
                
                print("[1] Sending PM, PO to M")
                plaintext = "PMPO" + "@@@" + str(m) + "@@@" + str(cryptedK)
                connection.sendall(plaintext.encode())
                
                start_exchange = time.time()
        except:
            server_stopped = True
            break

def client_program():
    global connection
    global server_stopped
    global K
    global PubKC
    global PriKC

    host = socket.gethostname()
    port = 5000

    accepted = False
    connection = socket.socket()
    
    while not accepted:
        try:
            connection.connect((host, port))
            accepted = True
            print("Connected to M")
        except:
            print("Waiting for M to open...")
    
    K = os.urandom(32)
    print("---Generated AES session key---")
    PriKC = generate_RSA_private_key()
    PubKC = PriKC.public_key()
    print("---Generated RSA keys---")

    threading.Thread(target=handle_read, args=(), daemon=True).start()
    threading.Thread(target=handle_write, args=(), daemon=True).start()
    while not server_stopped:
        pass

    connection.close()
    
    server_stopped = False
    print("Server closed")
    client_program()

client_program()
