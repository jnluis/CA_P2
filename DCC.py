import datetime
import json
from dataclasses import asdict, dataclass, field
from typing import Iterable

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.hashes import SHA3_512, SHA384, Hash
from cryptography.x509 import load_pem_x509_certificate


@dataclass(frozen=True)
class Identity_Attribute:
    _password: str = field(repr=False, compare=False)
    _pseudo_random_mask: str = field(init=False)
    label: str = ""
    value: str = ""
    commitment_value: str = field(init=False)

    def __post_init__(self):
        hash = Hash(SHA3_512())
        hash.update((self.label + self._password).encode())
        object.__setattr__(self, '_pseudo_random_mask', hash.finalize().hex())

        hash = Hash(SHA384())
        hash.update((self.label + self.value + self._pseudo_random_mask).encode())
        object.__setattr__(self, 'commitment_value', hash.finalize().hex())

    def __hash__(self):
        return hash((self.label, self.value))

def generate_identity_attributes(password: str, attributes: dict[str, str]) -> set[Identity_Attribute]:
    identity_attributes = set()
    for label, value in attributes.items():
        identity_attributes.add(Identity_Attribute(password, label, value))
    return identity_attributes

@dataclass
class Public_Key:
    key: Ed448PublicKey = None
    algorithm: str = ""

    def to_pem(self):
        return self.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

@dataclass
class Signature:
    signature_value: str = ""
    timestamp: str = ""
    algorithm: str = "Ed448"

@dataclass
class Issuer_Signature(Signature):
    issuer_certificate: str = ""

@dataclass
class DCC:
    identity_attributes: set[Identity_Attribute] = field(default_factory=set[Identity_Attribute])
    attributes_digest_description: str = "SHA-3_512 for pseudo-random mask and SHA-384 for commitment value"
    owner_public_key: Public_Key = field(default_factory=Public_Key)
    issuer_private_key: RSAPrivateKey = None
    issuer_certificate: str = ""
    issuer_signature: Issuer_Signature = field(init=False)

    def __post_init__(self):
        if self.issuer_private_key is None:
            raise ValueError("Issuer private key must be provided.")
        self.sign_attributes(self.issuer_private_key)

    def disclose_attributes(self, attribute_names, password):
        """
        Disclose a subset of attributes and provide their proof of correctness.
        :param attribute_names: List of attribute labels to disclose.
        :param password: Password used to generate pseudo-random masks.
        :return: List of disclosed attributes with their proofs.
        """
        disclosed = []
        for attr in self.identity_attributes:
            if attr.label in attribute_names:
                # Recalculate commitment value for verification
                hash = Hash(SHA384())
                hash.update((attr.label + password).encode())
                pseudo_random_mask = hash.finalize()

                hash = Hash(SHA384())
                hash.update(attr.label.encode() + attr.value.encode() + pseudo_random_mask)
                calculated_commitment = hash.finalize().hex()

                if calculated_commitment == attr.commitment_value:
                    disclosed.append({
                        "label": attr.label,
                        "value": attr.value,
                        "commitment_value": attr.commitment_value
                    })
                else:
                    raise ValueError(f"Commitment value mismatch for attribute: {attr.label}")
        return disclosed

    def sign_attributes(self, private_key: RSAPrivateKey):
        """
        Sign the commitment values and public key to ensure integrity and ownership.
        :param private_key: RSA Private key for signing.
        """
        data_to_sign = (
            "".join(attr.commitment_value for attr in self.identity_attributes) +
            self.owner_public_key.to_pem().decode()
        ).encode()

        signature = private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(SHA384()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            SHA384()
        )

        self.issuer_signature = Issuer_Signature(
            signature_value=signature.hex(),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            algorithm="RSA-4096",
            issuer_certificate=self.issuer_certificate
        )

    @staticmethod
    def validate_signature(owner_public_key: Public_Key, issuer_signature: Issuer_Signature, commitment_values: Iterable[str]):
        """
        Validate the signature over the commitment values and public key.
        :return: True if valid, False otherwise.
        """
        data_to_validate = (
            "".join(commitment_values) +
            owner_public_key.to_pem().decode()
        ).encode()

        try:
            certificate = load_pem_x509_certificate(issuer_signature.issuer_certificate.encode(), backend=default_backend())
            issuer_public_key = certificate.public_key()
        except Exception as e:
            print(f"Error loading issuer certificate: {e}")
            return False

        try:
            issuer_public_key.verify(
                bytes.fromhex(issuer_signature.signature_value),
                data_to_validate,
                padding.PSS(
                    mgf=padding.MGF1(SHA384()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                SHA384()
            )
            return True
        except Exception:
            return False

    def __repr__(self):
        """
        Convert the DCC object into a JSON serializable dictionary.
        """
        # Convert identity attributes to a list of dictionaries
        attributes = [
            {"label": attr.label, "value": attr.value, "commitment_value": attr.commitment_value}
            for attr in self.identity_attributes
        ]

        return json.dumps({
            "identity_attributes": attributes,
            "attributes_digest_description": self.attributes_digest_description,
            "owner_public_key": {
                "key": self.owner_public_key.to_pem().decode(),
                "algorithm": self.owner_public_key.algorithm
            },
            "issuer_signature": asdict(self.issuer_signature),
        }, indent=2)

