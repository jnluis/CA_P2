from dataclasses import dataclass, field, asdict
from cryptography.hazmat.primitives.hashes import Hash, SHA384
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey
from cryptography.hazmat.primitives import serialization
import json
import datetime

@dataclass(frozen=True)
class Identity_Attribute:
    _password: str = field(repr=False, compare=False)
    label: str = ""
    value: str = ""
    commitment_value: str = field(init=False)

    def __post_init__(self):
        hash = Hash(SHA384())
        hash.update((self.label + self._password).encode())
        pseudo_random_mask = hash.finalize()

        hash = Hash(SHA384())
        hash.update(self.label.encode() + self.value.encode() + pseudo_random_mask)
        object.__setattr__(self, 'commitment_value', hash.finalize().hex())

    def __hash__(self):
        return hash((self.label, self.value))

@dataclass
class Public_Key:
    key: RSAPublicKey = None
    algorithm: str = "RSA"

    def to_pem(self):
        return self.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

@dataclass
class Issuer_Signature:
    signature_value: str = ""
    timestamp: str = ""
    algorithm: str = "RSA"
    issuer_certificate: str = ""

@dataclass
class DCC:
    identity_attributes: set = field(default_factory=set())
    attributes_digest_description: str = "SHA-384 for pseudo-random mask and SHA-384 for commitment value"
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
            timestamp=datetime.datetime.utcnow().isoformat(),
            algorithm="RSA-2048",
            issuer_certificate=self.issuer_certificate
        )

    def validate_signature(self):
        """
        Validate the signature over the commitment values and public key.
        :return: True if valid, False otherwise.
        """
        data_to_validate = (
            "".join(attr.commitment_value for attr in self.identity_attributes) +
            self.owner_public_key.to_pem().decode()
        ).encode()

        try:
            self.owner_public_key.key.verify(
                bytes.fromhex(self.issuer_signature.signature_value),
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