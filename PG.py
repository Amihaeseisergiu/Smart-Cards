from crypto import *

PubKPG = None
PriKPG = None
PubKM = None
K = None
iv = b'\xc1\xa3\xd9\x8f\x93~4\xa8(\xdci/!\xf5\x80\xc4'
server_stopped = False
connection = None

with open("./public_key_M.pem", "rb") as key_file:
     PubKM = serialization.load_pem_public_key(key_file.read())
with open("./public_key_PG.pem", "rb") as key_file:
     PubKPG = serialization.load_pem_public_key(key_file.read())
with open("./private_key_PG.pem", "rb") as key_file:
     PriKPG = serialization.load_pem_private_key(key_file.read(), password=None)

def handle_read():
    global server_stopped
    global connection
    global PriKPG
    global PubKM
    global K
    
    while not server_stopped:
        try:
            data = connection.recv(1000000)
            splitted = data.decode().split("@@@")
            
            if splitted[0] == "PMandSignature":
                m = splitted[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted[2][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKPG, cryptedK)
                print("[1] Received PM and signature of Sid,PubKC,Amount")
                
                PM_and_signature = decrypt_AES(decryptedK, iv, m)
                PM = PM_and_signature.decode().rsplit("@@@", 1)[0]
                splitted_PM = PM.split("@@@")
                
                m = splitted_PM[0][2:-1].encode().decode('unicode_escape').encode('latin-1')
                cryptedK = splitted_PM[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                decryptedK = decrypt_RSA(PriKPG, cryptedK)
                PM = decrypt_AES(decryptedK, iv, m)
                
                signature = PM.decode().rsplit("@@@", 1)[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                PubKC = serialization.load_pem_public_key(PM.decode().rsplit("@@@", 4)[1][2:-1].encode().decode('unicode_escape').encode('latin-1'))
                PubKC_bytes = PM.decode().rsplit("@@@", 4)[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                PI = PM.decode().rsplit("@@@", 1)[0]
                
                if verify_RSA(PubKC, signature, PI.encode()):
                    print("[2] Signature of PI matches")
                    
                    Sid = PM.decode().split("@@@")[3]
                    Amount = PM.decode().split("@@@")[4]
                    NC = PM.decode().split("@@@")[6]
                    
                    s = "@@@"
                    to_verify = Sid + s + str(PubKC_bytes) + s + Amount
                    signature = PM_and_signature.decode().rsplit("@@@", 1)[1][2:-1].encode().decode('unicode_escape').encode('latin-1')
                    
                    if verify_RSA(PubKM, signature, to_verify.encode()):
                        print("[3] Signature of Sid, PubKC, Amount matches")
                        
                        Resp = "yes"
                        to_sign = Resp + s + Sid + s + Amount + s + NC
                        signature = sign_RSA(PriKPG, to_sign.encode())
                        
                        Resp_and_signature = Resp + s + Sid + s + str(signature)
                        m = encrypt_AES(K, iv, Resp_and_signature.encode())
                        cryptedK = encrypt_RSA(PubKM, K)
                        
                        print("[4] Sending Resp, Sid and signature to M")
                        plaintext = "RespandSignature" + "@@@" + str(m) + "@@@" + str(cryptedK)
                        connection.sendall(plaintext.encode())
                    else:
                        print("[3] Signature of Sid, PubKC, Amount doesn't match. Aborting...")
                        server_stopped = True
                        break
                else:
                    print("[2] Signature of PI doesn't match. Aborting...")
                    server_stopped = True
                    break
        except:
            server_stopped = True
            break
        
def handle_write():
    global server_stopped
    global connection
    
    while not server_stopped:
        try:
            message = input()
            connection.sendall(message.encode())
        except:
            server_stopped = True
            break

def server_program():
    global connection
    global server_stopped
    global K

    host = socket.gethostname()
    port = 5001

    server_socket = socket.socket()
    server_socket.bind((host, port))

    server_socket.listen(1)
    connection, address = server_socket.accept()
    print("M connected")
    
    K = os.urandom(32)
    print("---Generated AES session key---")
    
    threading.Thread(target=handle_read, args=(), daemon=True).start()
    threading.Thread(target=handle_write, args=(), daemon=True).start()
    while not server_stopped:
        pass

    connection.close()
    
    print("Merchant left. Restarting server...")
    server_stopped = False
    server_socket.close()
    server_program()

server_program()