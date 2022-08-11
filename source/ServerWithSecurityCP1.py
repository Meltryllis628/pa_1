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

def encrypt(message,public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
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
    return decrypted_message

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

def sign(private_key,file_data):
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

def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)

pri = None

def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()
                            file_data = b""
                            file_len = 0
                            block_num = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            for i in range(block_num):
                                file_len = convert_bytes_to_int(
                                    read_bytes(client_socket, 8)
                                )
                                block_encrypted = read_bytes(client_socket, file_len)
                                # print(file_data)
                                block_data = decrypt(block_encrypted,pri)
                                file_data += block_data
                            filename = "recv_" + filename.split("/")[-1]

                            # Write the file with 'recv_' prefix
                            with open(
                                f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            file_len = convert_bytes_to_int(read_bytes(client_socket, 8)) 
                            # print("<-")
                            # print(file_len)
                            file_data = read_bytes(client_socket, file_len)
                            # print("<-")
                            # print(file_data)
                            pri = load_private_key("../source/auth/_private_key.pem")
                            encrypted_file_data = sign(pri,file_data)
                            client_socket.sendall(convert_int_to_bytes(len(encrypted_file_data)))
                            # print("->")
                            # print(len(encrypted_file_data))
                            client_socket.sendall(encrypted_file_data)
                            # print("->")
                            # print(encrypted_file_data)
                            with open("../source/auth/server_signed.crt","rb")as file:
                                certification = file.read()
                            client_socket.sendall(convert_int_to_bytes(len(certification)))
                            # print("->")
                            # print(len(certification))
                            client_socket.sendall(certification)
                            # print("->")
                            # print(certification)

    except Exception as e:
        print(e)
        s.close()


if __name__ == "__main__":
    main(sys.argv[1:])
