from flask import Flask, request, jsonify
from service import *
from dropboxService import *

app = Flask(__name__)

#request to join group, stores unapproved cert in pending
@app.route("/requestCert", methods=["POST"])
def request_cert():
    data = request.get_json()
    email = data.get("email")          #new user sends their email
    #they are given a cert and private key, cert is useless until
    #user is approved by admin as they will not be in approvedRequests
    #if user is set to admin, error
    if email.strip().lower() == "admin":
        return jsonify({"error": "Cannot request cert for admin"}), 403
    key, cert = createUserCert(email) 
    #return json with email, cert and key
    return jsonify({    
        "email": email,
        "cert": cert,
        "key": key,
        "message": "Certificate pending Admin approval, please "
        "save both Private Key and Certificate Safely"
    })

#allows the administrator to check who is currently waitng for approval
@app.route("/checkPending", methods=["GET"])
def listPendingUsers():
    pendingUsers = getPending() #calls getPending
    return pendingUsers

#admin can approve users, allowing their cert to work
@app.route("/approveUser", methods=["POST"])
def approvePendingUser():
    pendingUsers = getPending()
    data = request.get_json()
    email = data.get("email") #admin submits email of person they want to approve
    if email in pendingUsers:
        approveCert(email)
        return f"Approved {email}\n"
    
#delete user from group, remove them from
#approvedRequests and delete their encrypted AES keys
@app.route("/deleteUser", methods=["POST"])
def removeUser():
    data = request.get_json()
    email = data.get("email")  #Admin submits email of user to remove
    if not email:
        return jsonify({"error": "Missing email"}), 400 #error if no email
    return deleteUser(email)

#users can upload files, files will be encrypted automatically,
@app.route("/uploadFile", methods=["POST"])
def uploadForApproved():
    try:
        newFile = request.files['file']  # get passed in file
        newFileBytes = newFile.read()    
        filename = newFile.filename      # get the file name

        # Encrypt file with AES
        EncryptedFile, AESkey = aesEncryption(newFileBytes)

        # Upload encrypted file to Dropbox
        uploadEncryptedFile(filename, EncryptedFile)

        # Get all approved users
        approvedUsers = getApproved()

        # Encrypt AES key for each user and upload
        for user in approvedUsers: 
            userPublicKey = getUserPublicKey(user)
            encryptedAESkey = encryptAESKey(userPublicKey, AESkey)
            uploadKeyToDropbox(filename, encryptedAESkey, user)

        return f"Uploaded file : {filename}"

    except Exception as e:
        return jsonify({"error": str(e)}), 500
                    

#a user uploads their cert and is given a list of the files they can download
@app.route("/listFiles", methods=["POST"])
def listFiles():
    #if user does not upload cert, error
    if 'cert' not in request.files:
        return jsonify({"error": "Missing cert"}), 400
    try:
        certFile = request.files['cert']      #get passed in cert
        cert = x509.load_pem_x509_certificate(certFile.read()) #return certificate object
        user = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value #get name attribute stored in cert when it was created
        files = listUserFiles(user)        #lisst files user has access to
        return jsonify({"email": user, "files": files})  #return them in json
    except Exception as e:
        return jsonify({"error":  str(e)}), 400
    
#a user provides their cert, privateKey and the file they wish to download
#(filename comes from /listFiles())
@app.route("/downloadFile", methods=["POST"])
def decryptAndDownload():
    #get cert, private key and name of file to download that are passed in
    certFile = request.files.get("cert")
    privateKeyFile = request.files.get("privateKey")
    filename = request.form.get("filename")
    #if any are not there, error
    if not certFile or not privateKeyFile or not filename:
        return jsonify({"error": "Missing file, cert, or private key"}), 400
    userCert = certFile.read().decode()
    cert = x509.load_pem_x509_certificate(userCert.encode()) #get user cert object
    #verify cert signature to make sur not self-signed
    try:
        adminPublicKey = adminCert.public_key()
        adminPublicKey.verify(   
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
    except Exception as e:
        return jsonify({"error": f"Certificate signature invalid: {str(e)}"}), 403
    #return user email
    user = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    #check if user approved
    if user not in getApproved():
        return jsonify({"error": f"{user} is not approved"}), 403
    keyFile = f"/keys/{filename}.{user}.key" #make path to key for file
    fileToDecrypt = f"/files/{filename}"     #file path
    encryptedAES = downloadUserAESKey(keyFile) #get the encypted AES key
    #reading in .key file breaks the \n from the /requestCert key
    keyString = privateKeyFile.read().decode() #convert from string to byte
    keyString = keyString.replace("\\n", "\n") #replace escaped newline with real
    keyBytes = keyString.encode() #convert to bytes again
    #Load user private key
    privateKey = ser.load_pem_private_key(
        keyBytes,
        password=None,
    )
    decryptedAESKey = decryptAESKey(privateKey, encryptedAES) #decrypt AES key using private RSA key
    decryptedFile = decryptFile(fileToDecrypt, decryptedAESKey) #decrypt file using decrypted AES key
    open("decrypted_output.pdf", "wb").write(decryptedFile) #store file temporarily in root
    return decryptedFile

#check who person using site is, admin or user and show page accordingly
@app.route("/whoami", methods=["POST"])
def whoami():
    userCert = None
    if 'cert' in request.files:
        certFile = request.files['cert']
        userCert = certFile.read().decode()
    elif request.form.get("cert"):
        userCert = request.form.get("cert")
    if not userCert:
            return jsonify({"error": "Missing cert"}), 400
    
    try:
        cert = x509.load_pem_x509_certificate(userCert.encode())
    except Exception:
        return jsonify({"error": "Invalid certificate format"}), 400
    
    #check cert is signed by admin private key
    try:
        adminPublicKey = adminCert.public_key()
        adminPublicKey.verify(
                cert.signature,  #signature on cert
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
    except Exception as e:
        return jsonify({"error": f"Certificate signature invalid: {str(e)}"}), 403

    #cert = x509.load_pem_x509_certificate(userCert.encode())
    #get 
    user = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    role = "admin" if user in {"admin"} else "user"  #if user is admin, role is admin, else they are user
    approved = getApproved()
    #return json
    if user in approved:
        return jsonify({"email": user, "role": "user", "approval": "approved"})
    elif role == "admin":
        return jsonify({"email": user, "role": "admin", "approval": "approved"})
    

if __name__ == "__main__":
    app.run()