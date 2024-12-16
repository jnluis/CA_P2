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

issuer_private_key = ""

def generate_issuer_certificate():
    global private_key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)

    subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Aveiro"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Esgueira"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CA_ISSUER"),
    x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10) # Our certificate will be valid for 10 days
    ).sign(private_key, hashes.SHA256())

    with open("issuer_certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    

def main():
    identity_attributes = list()
    identity_attributes.append(Identity_attribute("nome", "Marcolino", "password1"))
    identity_attributes.append(Identity_attribute("data_nascimento", "24/02/1999", "password1"))

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    print(identity_attributes)
    print("\n")
    print(pem)
    
    public_key = Public_key(pem.decode("UTF-8"), "RSA-2048")
    print(public_key)



    generate_issuer_certificate()
    with open("issuer_certificate.pem", "rb") as f:
        certificate = f.read().decode("UTF-8")
    issuer_signature = Issuer_signature("signature_value", "timestamp", "algorithm", certificate)
    print(issuer_signature)

if __name__ == '__main__':
    main()