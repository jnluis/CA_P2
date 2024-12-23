from DCC import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime
import socket
import json

issuer_private_key = None  # Global variable to hold the issuer's private key
RSA_KEY_SIZE = 4096  # Size of the RSA key pair

def generate_issuer_certificate():
    """
    Generates an RSA private key and corresponding self-signed certificate for the issuer.
    Saves the certificate to a file.
    """
    global issuer_private_key
    issuer_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = issuer_private_key.public_key()

    # Define certificate details
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Aveiro"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Esgueira"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA_ISSUER"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    # Build and sign the certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)  # Valid for 10 days
    ).sign(issuer_private_key, hashes.SHA256())

    # Save the certificate to a file
    with open("issuer_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def start_server():
    HOST = '127.0.0.1'  # Localhost
    PORT = 65432        # Port to listen on

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        print("Server is listening...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive signed data
            data = conn.recv(1024)
            if data:
                try:
                    # Decode and parse JSON data
                    received_data = json.loads(data.decode('utf-8'))
                    print(f"Received data: {received_data}")
                    # Extract received values
                    attributes = received_data.get("attributes", {})
                    password = received_data.get("password", "")
                    public_key_hex = received_data.get("public_key", "")
                    CC_used = received_data.get("CC", 0)

                    dcc = process_received_data(attributes, password, public_key_hex, CC_used)

                    # Send response
                    data_length = len(dcc)
                    conn.sendall(data_length.to_bytes(4, 'big'))

                    conn.sendall(dcc.encode('utf-8'))
                    print("Response sent.")

                except json.JSONDecodeError as e:
                    print(f"Failed to parse JSON: {e}")
                    conn.sendall(b"Invalid JSON format!")

def process_received_data(attributes, password, public_key_hex, CC_used):
    """
    Process the received attributes and generate the DCC using the provided values.
    """
    # Step 1: Map attributes into Identity_Attribute objects
    identity_attributes = []
    for label, value in attributes.items():
        identity_attributes.append(Identity_Attribute(password, label, value))

    # Step 2: Generate the owner's public key from the received public key (hex)
    public_key_bytes = bytes.fromhex(public_key_hex)  # Convert hex to bytes
    owner_public_key = serialization.load_der_public_key(public_key_bytes)

    # Wrap the public key in the PublicKey class
    if CC_used == 1:
        public_key_obj = Public_Key(key=owner_public_key, algorithm=f"CC public key algorithm") # TODO: Add the correct algorithm
    else:
        public_key_obj = Public_Key(key=owner_public_key, algorithm=f"ED448")

    # Step 3: Generate issuer's certificate
    generate_issuer_certificate()
    with open("issuer_certificate.pem", "rb") as f:
        issuer_certificate = f.read().decode("UTF-8")

    # Step 4: Create the DCC
    dcc = DCC(
        identity_attributes=set(identity_attributes),
        owner_public_key=public_key_obj,
        issuer_private_key=issuer_private_key,
        issuer_certificate=issuer_certificate
    )

    return dcc.__repr__()

if __name__ == '__main__':
    start_server()
