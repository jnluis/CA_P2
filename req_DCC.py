from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.hazmat.primitives . serialization import load_der_public_key
from cryptography.hazmat.primitives . asymmetric import (
padding , rsa , utils
)
import socket
from datetime import datetime, timezone
from pyasn1.codec.der.decoder import decode
from pyasn1.type.univ import Sequence
import json

lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

def get_birth_date_from_extension(extension):
    try:
        decoded_value, _ = decode(extension)
        for seq in decoded_value:
            if isinstance(seq, Sequence):
                oid = str(seq[0])  # Extract the OID
                if oid == "1.3.6.1.5.5.7.9.1":  # Birth Date OID
                    # Extract the associated value
                    birth_date_raw = seq[1][0]  # Get the SetOf value
                    birth_date_str = birth_date_raw.asOctets().decode()  # Convert to string
                    
                    # Convert the string to a datetime object
                    birth_date = datetime.strptime(birth_date_str, "%Y%m%d%H%M%SZ")
                    
                    # Set timezone to UTC (as 'Z' in the string indicates UTC)
                    birth_date = birth_date.replace(tzinfo=timezone.utc)
                    
                    return birth_date
        return None 
    except Exception as e:
        print(f"Error decoding subjectDirectoryAttributes: {e}")
        return None

def loadCC_and_sign():
    attributes = {} 
    for slot in slots :
        if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session = pkcs11.openSession(slot)
            privKey = session.findObjects( [(CKA_CLASS , CKO_PRIVATE_KEY ) , ( CKA_LABEL , 'CITIZEN AUTHENTICATION KEY' )] ) [0]
            pubKey = session.findObjects([(CKA_CLASS,CKO_PUBLIC_KEY),( CKA_LABEL , 'CITIZEN AUTHENTICATION KEY')])[0]
            #signature = bytes( session.sign( privKey , data , Mechanism ( CKM_SHA1_RSA_PKCS ) ))
           
            cert = session.findObjects([
                (CKA_CLASS, CKO_CERTIFICATE),
                (CKA_LABEL, 'CITIZEN AUTHENTICATION CERTIFICATE')  # Label for the authentication certificate
            ])[0]

            # Retrieve the certificate value
            certDer = session.getAttributeValue(cert, [CKA_VALUE], True)[0]
            certBytes = bytes(certDer)  # Convert to bytes

            # Parse the certificate using cryptography
            certificate = x509.load_der_x509_certificate(certBytes, default_backend())

            # Extract personal details from the certificate subject
            subject = certificate.subject
            for ex in certificate.extensions:
                oid = ex.oid.dotted_string
                if oid == "2.5.29.9":  # subjectDirectoryAttributes OID
                   birth_date = get_birth_date_from_extension(ex.value.value) 

            name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            serial_number = subject.get_attributes_for_oid(x509.NameOID.SERIAL_NUMBER)[0].value
            country = subject.get_attributes_for_oid(x509.NameOID.COUNTRY_NAME)[0].value

            attributes['birth_date'] = birth_date.isoformat() 
            attributes['name'] = name
            attributes['serial_number'] = serial_number
            attributes['country'] = country

            pubKeyDer = session.getAttributeValue(pubKey, [CKA_VALUE], True)[0]
            pubKeyBytes = bytes(pubKeyDer)  # Convert to bytes

            session.closeSession
            return pubKeyBytes, attributes

def verify_signature(signature):
    for slot in slots :
        data = bytes('data to be signed', 'utf-8')
        session = pkcs11.openSession(slot)
        pubKeyHandle = session.findObjects([(CKA_CLASS,CKO_PUBLIC_KEY),( CKA_LABEL , 'CITIZEN AUTHENTICATION KEY')])[0]
        pubKeyDer = session.getAttributeValue(pubKeyHandle,[CKA_VALUE],True)[0]
        session.closeSession
        pubKey = load_der_public_key(bytes(pubKeyDer), default_backend() )

        try :
            pubKey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
            print('Verification succeeded')
        except:
            print('Verification failed')   

def send_signed_data(pubKeyBytes, attributes, password):
    HOST = '127.0.0.1'  # Server address
    PORT = 65432        # Server port

    data = {
        "attributes": attributes,
        "password": password,
        "public_key": pubKeyBytes.hex()  # Convert binary to hexadecimal string
    }

    json_data = json.dumps(data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((HOST, PORT))  # Connect to the server

        # Send signed data
        client_socket.sendall(json_data.encode('utf-8'))
        print("Signed data sent successfully.")

        # Wait for response from server
        response = client_socket.recv(1024)
        print(f"Response from server: {response.decode()}")  # Decode and print response                     

def main():
    while True:
        password= input("Enter a password ")

        print("1. Request DCC")
        print("2. Request DCC with CC")
        print("3. Request min-DCC with CC")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            person_name = input("Enter the person's name: ")
            #dcc = owner.request_dcc(person_name)
            #print(f"DCC requested: {dcc}")
        elif choice == '2':
            pubKeyBytes, attributes =loadCC_and_sign()

            # if para se for um gen ou um gen_min
            send_signed_data(pubKeyBytes, attributes, password)
            #verify_signature(signature)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()