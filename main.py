# Python server 2 program
import base64
import itertools
import os
import pickle
import subprocess
import rsa
from Cryptodome.Cipher import PKCS1_OAEP
import hashlib
from Cryptodome.PublicKey import RSA
import OpenSSL.crypto
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from asn1crypto.keys import RSAPrivateKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import json
import socket
import sqlite3
from random import randint

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.hashes import HashAlgorithm


def hash_encrypt(plaintext):
    """
       make hash encryption to string
       """
    hash_object = hashlib.sha256(plaintext.encode('utf-8'))
    hash_hex = hash_object.hexdigest()
    return hash_hex





def get_d(e, phi):
    """
    Compute d such that e * d = 1 % phi.
    """
    for i in itertools.count(start=int(phi / e)):
        v = (e * i) % phi
        if v == 1:
            break
    return i

p = 19
q = 29
n = p * q
num1 = q - 1
num2 = p - 1
phi = num2 * num1
e = 17
d = get_d(e, phi)
public_key = (n, e)
private_key = (n, d)

def encryption(lst):
    """
       make rsa encryption (i^e) % n on every number in the list
       """
    return [pow(i, e, n) for i in lst]

def decryption(encMessage):
    """
       make the encrypt message list and decrypt the rsa encryption (i^d) % n on every number in the list
       and make the decrypt number char and append the char to a string till i have the decrypted message
       """
    lst = encMessage.split(",")
    print(lst)
    message = [pow(int(i), d, n) for i in lst]
    return "".join(chr(i) for i in message)

def doEnc(message):
    """
       make a list of the ascci values of the chars in the string message, send them to the function encryption
        that encrypts them and make a string of the encrypted numbers that separated with ,
       """
    lst = []
    for i in message:
        lst.append(ord(i))
    encrypt = encryption(lst)
    encMessage = ""
    # build the encrypt message
    for i in range(len(encrypt)):
        if i != len(encrypt) - 1:
            encMessage += str(encrypt[i]) + ","
        else:
            encMessage += str(encrypt[i])
    return encMessage

def receive_data(conn):
    # Receive the padded length
    padded_length = conn.recv(10).decode()
    length = int(padded_length.strip())

    # Receive the data in chunks
    received_data = b""
    while length > 0:
        chunk = conn.recv(min(1024, length))
        if not chunk:
            break
        received_data += chunk
        length -= len(chunk)

    actual_data = received_data.decode()
    return actual_data


def doDec(message):
    """
       send the message to the decryption function
       """
    return decryption(message)
# Main Program
try:
    conn = sqlite3.connect('user.db')
    con = conn.cursor()
    print("Opened database successfully")
except:
    print("Cannot opr or create db")
conn.execute('''CREATE TABLE IF NOT EXISTS USERS
(USER_NAME TEXT PRIMARY KEY NOT NULL,
PASSWORD TEXT NOT NULL,
SCORE INT NOT NULL);
''')
print("Table created successfully");
server_socket = socket.socket()
server_socket.bind(('0.0.0.0', 8820))
try:
    while True:
        server_socket.listen(1)
        print("Waiting for new connection ....")
        (client_socket, address) = server_socket.accept()
        print("log in")
        dic_in = json.loads(doDec(receive_data(client_socket)[:-1]))
        ls = dic_in["ls"]
        if ls == "sign up":
            user_name = dic_in["user_name"]
            password = dic_in["password"]
            result = con.execute("""SELECT USER_NAME FROM USERS WHERE USER_NAME=?""", (user_name,))
            if result.fetchone() is None:
                conn.execute('''INSERT INTO ''' + '''USERS''' + ''' (USER_NAME,PASSWORD,SCORE) VALUES (?,?,?) ''', (user_name, hash_encrypt(password), 1))
                conn.commit()
                json_out = json.dumps(dic_in)
                str_send = doEnc(json_out)
                padded_length = str(len(str_send)).zfill(10)
                client_socket.send((padded_length + str_send).encode())
            else:
                dic_out = {"error": "There is a user name like that"}
                json_out = json.dumps(dic_out)
                str_send = doEnc(json_out)
                padded_length = str(len(str_send)).zfill(10)
                client_socket.send((padded_length + str_send).encode())

        elif ls == "login":
            user_name = dic_in["user_name"]
            password = dic_in["password"]
            result = con.execute("""SELECT USER_NAME FROM USERS WHERE USER_NAME=? AND PASSWORD=?""", (user_name, hash_encrypt(password),))

            if result.fetchone() is None:
                dic_out = {"error": "There is not a user name like that"}
                json_out = json.dumps(dic_out)
                str_send = doEnc(json_out)
                padded_length = str(len(str_send)).zfill(10)
                client_socket.send((padded_length + str_send).encode())
            else:
                json_out = json.dumps(dic_in)
                str_send = doEnc(json_out)
                padded_length = str(len(str_send)).zfill(10)
                client_socket.send((padded_length + str_send).encode())
        elif ls == "score":
            user_name = dic_in["user_name"]
            result = con.execute("""SELECT SCORE FROM USERS WHERE USER_NAME=?""", (user_name,))
            result1 = result.fetchone()[0] + dic_in["score"]
            print(result.fetchone())
            conn.execute('''UPDATE USERS SET SCORE = ? WHERE USER_NAME = ?''', (result1, user_name,))
            conn.commit()
        elif ls == "count_table":
            result = con.execute("""SELECT SCORE, USER_NAME FROM USERS""")
            dic_out = str(result.fetchall())
            print(dic_out)
            str_send = doEnc(dic_out)
            padded_length = str(len(str_send)).zfill(10)
            client_socket.send((padded_length + str_send).encode())
        print(dic_in)
        print("Closing connection with Client ....")
        client_socket.close()
except KeyboardInterrupt:
    server_socket.close()
server_socket.close()



