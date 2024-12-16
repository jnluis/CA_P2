import PyKCS11
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Path to the PKCS#11 library
lib = '/usr/local/lib/libpteidpkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slots = pkcs11.getSlotList()

for slot in slots:
    print(
        "==============================================================================================="
    )
    print(pkcs11.getTokenInfo(slot))
    print(
        "==============================================================================================="
    )

    session = pkcs11.openSession(slot)
    
    # Find objects of class CKO_CERTIFICATE (1)
    for obj in session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
        # Get the attributes of the certificate
        attr = session.getAttributeValue(obj, [PyKCS11.CKA_VALUE])
        cert_der = bytes(attr[0])  # Get the certificate in DER format

        # Load the certificate using the cryptography library
        cert = x509.load_der_x509_certificate(cert_der, backend=default_backend())

        # Print the subject (name and other details)
        print("Certificate Subject:")
        print(cert.subject)

        # Optionally, print issuer and other information
        print("Certificate Issuer:")
        print(cert.issuer)

    print(
        "==============================================================================================="
    )
