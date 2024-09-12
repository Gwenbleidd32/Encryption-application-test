#All encompassing shared message application

#Build Notes: 3 Selector options
#1. Send a message -> Enter a passphrase to encrypt and write a message to a shared folder/server.
#2. Receive a message -> Enter a passphrase to decrypt and read a message. -> Design a failover for message not found
#3. Quit -> Exit the application.

#Change this value to the path of your shared folder
file_path ="../exchange_point/proxy.txt"
#Change this value to the path of your mailbox
mailbox_path = "../site_2/mailbox/mail.txt"

#Libraries and Tools
import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
#>>>
#Functions

#Key-Maker-Function
def key_maker(passphrase, salt=b'fixed_salt_value'):
    """Creates a key for encrypting messages."""

    # Creating a key from the passphrase
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, #256 bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return key

#Message encryption function
def hermes(message,key):
    """Encrypts a message using a AES and generated key."""

    #AES encryption initilization
    iv = os.urandom(16) #Generating a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()) #Creating a cipher object
    encryptor = cipher.encryptor() #Creating an encryptor object
    #Padding the message
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    #Encrypting padded message
    secret = encryptor.update(padded_message) + encryptor.finalize()
    return secret, iv

#Message decryption function
def perseus(encrypted_message, iv, key):
    """Decrypts a message using AES and a generated key."""

    # initilize decryption cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    #Decrypting the message
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    #Unpadding the message
    unpadder = padding.PKCS7(128).unpadder()
    truth = unpadder.update(decrypted_padded_message) + unpadder.finalize()
    return truth.decode()
#>>>

#Greetings
print("Welcome to Araska Secure messaging system!\n>>>")
#>>>
allez = True
while allez:
    #Main Menu
    print("Please select an option from the below numbers:\n"
          "{1} Send a message\n{2} Receive a message\n>>>\nOr type (Q or q) to exit\n>>>")
    choice = input("-->:")
    #>>>

    #Message encryption and delivery tool
    if choice == '1':
        #Key generation
        key_choice1 = input("Please enter a value to generate a key:\n-->:")
        key = key_maker(key_choice1)# function call 
        print(">>>:Key has been logged!")
        #>>>

        #Message encryption
        message = input("Please enter a message to be encrypted:\n-->:")
        secret, iv = hermes(message, key)#function call
        #>>>

        #Writing the encrypted message and vector to the shared folder
        with open(file_path,"wb") as delivery:
            delivery.write(iv + secret)
        print(">>>:Message has been encrypted and sent!")
        #>>>

    #Message retreival and decryption tool.
    elif choice == '2': 
        #Key generation
        key_choice2 = input("Please enter a passphrase to decrypt the message:\n-->:")
        key = key_maker(key_choice2)#function call``
        #>>>

        #Failover incase there is no message to decrypt
        if not os.path.exists(file_path):
            print(">>>:No message to decrypt")
            #>>>

        #Reading and decryption of the message
        else:
            try:
                with open(file_path, "rb") as delivery:
                    data= delivery.read()

                    iv = data[:16] #vector  
                    secret = data[16:] # Remaining Message

                #Decrypting the message using the function and corresponding key
                decrypted_message = perseus(secret, iv, key)

                with open(mailbox_path, "w") as mail:
                    mail.write(decrypted_message)
                print(">>>:Message has been Decrypted!")

            except Exception as e:
                print(f"Error Failed to decrypt: {e}")
                #>>>
                    
    #Exit Block
    elif choice.lower() == 'q':
        break
    #>>> ->:Prompt to make another request or close the application
    continuation = input(">>>\nPress any key to make another request or type(n) to exit the application\n-->:")
    if continuation.lower() == 'n':
        allez = False
    elif continuation.lower() == 'y':
        print(">>>")
        continue
#>>>

#Closing Statements
print(">>>")
print("Closing application!")


    
