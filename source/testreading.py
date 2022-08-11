import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from yaml import DirectiveToken

def load_private_key(path):
    with open(path,"rb")as file:
        #certification = x509.load_pem_x509_certificate(file.read())
        private_key = serialization.load_pem_private_key(file.read(),None)
        return private_key

def private_key(data):
    private_key = serialization.load_pem_private_key(data,None)
    return private_key

def load_public_key(path):
    with open(path,"rb")as file:
        certification = x509.load_pem_x509_certificate(file.read())
        public_key = certification.public_key()
        t0 = time.time()
        t2 = time.mktime(certification.not_valid_after.timetuple())
        t1 = time.mktime(certification.not_valid_before.timetuple())
        valid = (t0>t1)and(t0<t2)
        return public_key,valid

def public_key(data):
    certification = x509.load_pem_x509_certificate(data)
    public_key = certification.public_key()
    t0 = time.time()
    t2 = time.mktime(certification.not_valid_after.timetuple())
    t1 = time.mktime(certification.not_valid_before.timetuple())
    valid = (t0>t1)and(t0<t2)
    return public_key,valid

def sign(private_key,path):
    with open(path,"rb")as file:
        file_data=file.read()
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
        hashes.SHA256(),  # Algorithm to hash the file_data before signing
        )
    return signature

def vertify(signature,public_key,path):
    with open(path,"rb")as file:
        file_data=file.read()
        try:
            public_key.verify(
                signature,
                file_data,
                padding.PSS( 
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception as e:
            return False

def encrypt(message,public_key):
    BLOCK_LENGTH = 62
    length = len(message)
    pos = 0
    encrypted_message = []
    while(pos<length):
        if(pos+BLOCK_LENGTH<length):
            message_block=message[pos:pos+BLOCK_LENGTH]
        else:
            message_block=message[pos:]
        encrypted_message_block = public_key.encrypt(
            message_block,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        pos+=BLOCK_LENGTH
        encrypted_message.append(encrypted_message_block)
    return encrypted_message

def decrypt(encrypted_message,private_key):
    decrypted_message = private_key.decrypt(
      encrypted_message, # in bytes
      padding.OAEP(      # padding should match whatever used during encryption
          mgf=padding.MGF1(hashes.SHA256()),
          algorithm=hashes.SHA256(),
          label=None,
        ),
    )
    return decrypted_message,len(decrypted_message)

pri = load_private_key("../source/auth/_private_key.pem")
pub,valid = load_public_key("../source/auth/server_signed.crt")
# kca = load_public_key("../source/auth/cacsertificate.crt")
# vertify("dick",kca,"../source/files/file.txt")
# sig = sign(pri,"../source/files/file.txt")
# result = vertify(sig,pub,"../source/files/file.txt")
# print(result)

path = "files/file.txt"
with open(path,"rb")as file:
    message = bytes(file.read())
print(message)
blklist = encrypt(message,pub)
print(blklist)
for blk in blklist:
    dec_mes,len2 = decrypt(blk,pri)
    print(dec_mes)
    print(len2)