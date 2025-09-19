import dropbox
#access token is temporary, may need to be regenerated
dropboxAccessToken = ''
#upload encrpyted files to dropbox using their name and the encrypted file
def uploadEncryptedFile(filename, encryptedFile):
    filenameSafe = filename.replace(" ", "_")     #replace spaces to allign with dropbox formatting
    dropbox.Dropbox(dropboxAccessToken).files_upload(  #upload
        encryptedFile,              
        f"/files/{filenameSafe}",    #place in files folder
        mode=dropbox.files.WriteMode("overwrite")
    )

#upload a users RSA encrypted AES key
def uploadKeyToDropbox(filename, encryptedKey, user):
    filenameSafe = filename.replace(" ", "_") #necessary as before because filename is part of key 
    #userSafe = user.replace("@", "_at_")
    dropbox.Dropbox(dropboxAccessToken).files_upload(
        encryptedKey,
        f"/keys/{filenameSafe}.{user}.key",   #use filename, user and .key to indicate what file the key is for
        mode=dropbox.files.WriteMode("overwrite")
    )

#gets files that a particular user can access
def listUserFiles(user):
    #print(user)
    listFolder = dropbox.Dropbox(dropboxAccessToken).files_list_folder("/keys") #getall files in /keys
    files = []
    #files_list_folder returns list of metadata of files,
    #each entry is a fileMetaData() and has name inside it 
    for entry in listFolder.entries:
        if isinstance(entry, dropbox.files.FileMetadata) and entry.name.endswith(f".{user}.key"):
            tempName = entry.name.removesuffix(f".{user}.key") #remove ending of file to leave filename
            files.append(tempName) #left with names of files a user has a key to
    return files

#download a users Encrypted AES key
def downloadUserAESKey(keyFile):
    metadata, contentOfFile = dropbox.Dropbox(dropboxAccessToken).files_download(keyFile)
    encryptedKey = contentOfFile.content
    #print(encryptedKey)
    return encryptedKey

#download the encrypted file 
def downloadFile(filepath):
    metadata, contentOfFile = dropbox.Dropbox(dropboxAccessToken).files_download(filepath)
    encryptedFile = contentOfFile.content
    #print(encryptedFile)
    return encryptedFile

#remove files associated with a user
def deleteFromDropbox(email):
    listFolder = dropbox.Dropbox(dropboxAccessToken).files_list_folder("/keys") #get all files in /keys
    for entry in listFolder.entries:
        if isinstance(entry, dropbox.files.FileMetadata) and entry.name.endswith(f".{email}.key"):
            dropbox.Dropbox(dropboxAccessToken).files_delete(f"/keys/{entry.name}") #remove all a users keys


            


