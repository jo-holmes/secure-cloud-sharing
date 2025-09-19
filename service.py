import datetime
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives import hashes as hash
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509 import NameOID as OID
from dropboxService import *

#load admin cert and private key as they are stored locally
adminCert = x509.load_pem_x509_certificate(open("admin.crt", "rb").read())
adminKey = ser.load_pem_private_key(open("admin.key", "rb").read(), password=None)

#create admin cert, run only once or all certs issued become invalid
def createAdminCert(name="admin"):
    #generate private and public admin keys
    adminPrivateKey = rsa.generate_private_key(65537, 2048)
    adminPubKey = adminPrivateKey.public_key()
    #set identity attributes 
    subject = issuer = x509.Name([
        x509.NameAttribute(OID.ORGANIZATION_NAME, "Cloud Storage Group"), #set organization
        x509.NameAttribute(OID.COMMON_NAME, name) #set name as admin
    ])
    #from cryptography docs
    #create admin certificate, essentially a certificate authority to check other certs
    adminCert =( x509.CertificateBuilder().subject_name(subject)
    .issuer_name(issuer) 
    .public_key(adminPrivateKey.public_key()) #get public key from private
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))  #cant be valid before now
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)) #add how long it should be valid for to current time
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True) #CA is true as it issues other certs
    .sign(adminPrivateKey, hash.SHA256())
    )

#create cert for users
def createUserCert(userEmail):
    #generate user's private and public keys
    userPrivateKey , userPublicKey = generateRSAKeys() 
    subject = x509.Name([
        x509.NameAttribute(OID.COMMON_NAME, userEmail) #user name is email, set by admin to stop confusion
    ])
    #create user cert
    cert =( x509.CertificateBuilder().subject_name(subject)
    .issuer_name(adminCert.subject)  #issued by admin
    .public_key(userPublicKey)       #users public keys are also in their certs
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))  #cant be valid before now
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)) #add how long it should be valid for to current time
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) #ca = false as it is not the CA
    .sign(adminKey, hash.SHA256()) #signed by admin
    )
    #decode both user cert and private key
    decodedCert = cert.public_bytes(ser.Encoding.PEM).decode()
    decodedPrivateKey = userPrivateKey.private_bytes(
        encoding=ser.Encoding.PEM,
        format=ser.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=ser.NoEncryption()
    ).decode()
    #store user cert in pendingRequests folder, it isuseless until it is in approvedRequests
    with open(os.path.join("pendingRequests", f"{userEmail}.crt"), "w") as f:
        f.write(decodedCert)

    return decodedPrivateKey, decodedCert #return private key and cert to user

#generate RSA key pair
def generateRSAKeys():
    privateKey = rsa.generate_private_key(65537, 2048) #generate private rsa key
    publicKey = privateKey.public_key()                #get corresponding public key
    return privateKey, publicKey

#returns a list of pending users emails
def getPending():
    pendingUsers = []                                       #initialize 
    for file in os.scandir("pendingRequests"):              #go through files in pendingRequests
        if file.is_file() and file.name.endswith(".crt"):   #if file is a cert
            email = file.name.removesuffix(".crt")          #remove .crt file type
            pendingUsers.append(email)                      #left with email, return it
    return pendingUsers

#returns a list of approved users emails
def getApproved():
    approvedUsers = []
    for file in os.scandir("approvedRequests"):            #go through files in approvedRequests
        if file.is_file() and file.name.endswith(".crt"):  #if file is a cert
            email = file.name.removesuffix(".crt")         #remove .crt
            approvedUsers.append(email)                    #add usre to approvedUsers
    return approvedUsers

#move a pending request to approved
def approveCert(email):
    src = os.path.join("pendingRequests", f"{email}.crt")   #source path is in pendingRequests/{email}.crt
    dest = os.path.join("approvedRequests", f"{email}.crt") #destination is approvedRequests/{email}.crt
    return os.rename(src, dest)                             #use rename to essentially move the file

#delete a user from the group
def deleteUser(email):
    #check if they are pending or approved, remove from pending or approved
    if(os.path.exists(f"approvedRequests/{email}.crt")):
        os.remove(f"approvedRequests/{email}.crt")
    elif(os.path.exists(f"pendingRequests/{email}.crt")):
        os.remove(f"pendingRequests/{email}.crt")
    deleteFromDropbox(email)   #delete files related to user from the dropbox
    return f"Deleted {email}"


#encrypt file using AES encrytpion
def aesEncryption(file):
    iv = os.urandom(16)     #128 bit initialization vector
    AESkey = os.urandom(32) #256 bit aes key
    #padding needed as CBC used below can't encrypt partial blocks well
    #file needs to be divisible by 16 bytes
    requiredPadding = 16 - (len(file) % 16) #number of bytes to pad
    padding = []
    for x in range(requiredPadding):     #for the number of bytes to pad
        padding.append(requiredPadding)  #store the number of bytes to pad as padding
    paddedFile = file + bytes(padding)   #pad file by adding padding to end
    #from cryptography docs
    cipher = Cipher(algorithms.AES(AESkey), modes.CBC(iv))  #set up AES cipher with CBC mode
    encryptor = cipher.encryptor()
    aesEncryptedFile = encryptor.update(paddedFile) + encryptor.finalize() #update encrypts the file
    encryptedFileIv = iv + aesEncryptedFile       #add the iv to the front of the encrypted file so we can reuse it
    return encryptedFileIv, AESkey #return file and key and iv for decryption

#get a users public key from their cert
def getUserPublicKey(user):
    for file in os.scandir("approvedRequests"):   #for approved users
        if file.name.endswith(".crt") and file.name.removesuffix(".crt") == user: 
            with open(file.path, "rb") as f:
                userCert = x509.load_pem_x509_certificate(f.read()) #load cert object
                publicKey = userCert.public_key()                   #get public key
    return publicKey

#encrypt shared AES key with user's public RSA key from cert
def encryptAESKey(publicKey, aesKey):
    #from cryptography docs
    encryptedAES = publicKey.encrypt(aesKey, padding.OAEP(
        mgf=padding.MGF1(algorithm=hash.SHA256()),
        algorithm=hash.SHA256(),
        label=None
    ))
    return encryptedAES

#decrypt shared AES key with user's private RSA key
def decryptAESKey(privateKey, encryptedAES):
    #from cryptography docs
    decryptedAES = privateKey.decrypt(encryptedAES, padding.OAEP(
        mgf=padding.MGF1(algorithm=hash.SHA256()),
        algorithm=hash.SHA256(),
        label=None
    ))
    return decryptedAES

#decrypt the and encrypted file using path to file and AES key used to encrypt it 
def decryptFile(filepath, decryptedAESKey):
    encryptedFileIv = downloadFile(filepath) #get file from dropbox
    #iv was stored as first 16 bytes of file when it was encrypted
    iv = encryptedFileIv[:16] #take iv off file
    encryptedFile = encryptedFileIv[16:] #the ciphertext is everything after 16 bytes
    cipher = Cipher(algorithms.AES(decryptedAESKey), modes.CBC(iv))
    decryptor = cipher.decryptor()
    paddedFile = decryptor.update(encryptedFile) + decryptor.finalize() #decrypt paddedFile
    numberOfPaddingBytes = paddedFile[-1]     #last byte = how many bytes are padding
    decryptedFile = paddedFile[:-numberOfPaddingBytes] #remove padding
    return decryptedFile



    
