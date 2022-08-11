from inspect import signature
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

def vertify(signature,public_key,file_data):
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


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")
        arbitrary_message = b"assume this is an arbitraray message"
        s.sendall(convert_int_to_bytes(3))
        # print("<-")
        # print(convert_int_to_bytes(3))
        s.sendall(convert_int_to_bytes(len(arbitrary_message)))
        # print("<-")
        # print(convert_int_to_bytes(len(arbitrary_message)))
        s.sendall(arbitrary_message)
        # print("<-")
        # print(arbitrary_message)
        received_message1_length = convert_bytes_to_int(read_bytes(s,8))
        # print("->")
        # print(received_message1_length)
        encrypted_received_message1 = read_bytes(s,received_message1_length)
        # print("->")
        # print(encrypted_received_message1)
        received_message2_length = convert_bytes_to_int(read_bytes(s,8))
        print("->")
        print(received_message2_length)
        received_message2 = read_bytes(s,received_message2_length)
        print("->")
        print(received_message2)
        pub,valid = public_key(received_message2)
        if not valid:
            s.sendall(convert_int_to_bytes(2))
        signature = encrypted_received_message1
        if not vertify(signature,pub,arbitrary_message):
            s.sendall(convert_int_to_bytes(2))
 
        while True:
            # arbitrary_message = b"assume this is an arbitraray message"
            # s.sendall(convert_int_to_bytes(3))
            # s.sendall(convert_int_to_bytes(len(arbitrary_message)))
            # s.sendall(arbitrary_message)
            # received_message1_length = convert_bytes_to_int(read_bytes(s,8))
            # encrypted_received_message1 = read_bytes(s,received_message1_length)
            # received_message2_length = convert_bytes_to_int(read_bytes(s,8))
            # received_message2 = read_bytes(s,received_message2_length)
            # pub,valid = public_key(received_message2)
            # if not valid:
                # s.sendall(convert_int_to_bytes(2))
            # signature = encrypted_received_message1
            # if not vertify(signature,pub,arbitrary_message):
                # s.sendall(convert_int_to_bytes(2))
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(data)))
                s.sendall(data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
