# from PyKCS11 import *
# from PyKCS11.LowLevel import *

# lib = '/usr/local/lib/libpteidpkcs11.so'

# pkcs11 = PyKCS11.PyKCS11Lib()
# pkcs11.load(lib)
# slots = pkcs11.getSlotList()

# classes = {
#     CKO_PRIVATE_KEY : 'private key' ,
#     CKO_PUBLIC_KEY : 'public key' ,
#     CKO_CERTIFICATE : 'certificate'
# }

# for slot in slots :
#     if 'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
#         session = pkcs11.openSession(slot)
#         objects = session.findObjects()
#         for obj in objects:
#             l = session.getAttributeValue(obj, [CKA_LABEL])[0]
#             c = session.getAttributeValue(obj, [CKA_CLASS])[0]
#             value = session.getAttributeValue(obj, [CKA_VALUE])[0]
#             print('Object with label ' + l + ', of class' + classes[c])
#             print('Value:', value)

from DCC import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

issuer_private_key = None  # Global variable to hold the issuer's private key


def generate_issuer_certificate():
    """
    Generates an RSA private key and corresponding self-signed certificate for the issuer.
    Saves the certificate to a file.
    """
    global issuer_private_key
    issuer_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
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


def main():
    """
    Main function to generate a DCC for a person based on their identity attributes.
    """
    # Step 1: Define identity attributes
    identity_attributes = [
        Identity_Attribute("password1", "nome", "Marcolino"),
        Identity_Attribute("password1", "data_nascimento", "24/02/1999")
    ]

    # Step 2: Generate owner's RSA key pair
    owner_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    owner_public_key = owner_private_key.public_key()

    # Wrap the public key in the PublicKey class
    public_key_obj = Public_Key(key=owner_public_key, algorithm="RSA-2048")

    # Step 3: Generate issuer's certificate and load it
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

    # Step 5: Output the DCC details
    print("Generated DCC:")
    print(dcc)


if __name__ == '__main__':
    main()
