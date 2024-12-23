from dataclasses import dataclass, field, asdict
from DCC import Public_Key, Signature, Issuer_Signature, DCC
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.backends import default_backend
import base64
import json
import datetime

@dataclass
class minDCC:
    commitment_values: list = field(default_factory=list)
    attributes_digest_description: str = "SHA-3_512 for pseudo-random mask and SHA-384 for commitment values"
    identity_attributes: set = field(default_factory=set)
    owner_public_key: Public_Key = field(default_factory=Public_Key)
    owner_private_key: Ed448PrivateKey = None
    issuer_signature: Issuer_Signature = field(default_factory=Issuer_Signature)
    producer_signature: Signature = field(init=False)

    def __post_init__(self):
        if self.owner_private_key is None:
            raise ValueError("Owner private key must be provided.")
        self.sign_attributes(self.owner_private_key)

    def sign_attributes(self, private_key: Ed448PrivateKey):

        attributes = dict()
        for attr in self.identity_attributes:
            attributes[attr.label] = {
                "value": attr.value,
                "mask": attr._pseudo_random_mask,
            }

        data_to_sign = (
            "".join(commitment_value for commitment_value in self.commitment_values) +
            "".join(label + value + mask for label, attr in attributes.items() for value, mask in attr.items())
            .join(self.owner_public_key.to_pem().decode())
            .join(self.issuer_signature.signature_value)
        ).encode()

        try:
            private_key = load_pem_private_key(
                private_key.encode(),
                password=None,  # No password as Ed448 doesn't support encrypted PEM
                backend=default_backend()
            )

            # Ensure the loaded key is Ed448
            if not isinstance(private_key, Ed448PrivateKey):
                raise ValueError("The provided private key is not an Ed448 key.")
        except Exception as e:
            raise ValueError(f"Error loading private key: {e}")

        signature = private_key.sign(
            data_to_sign
        )

        self.producer_signature = Signature(
            signature_value=signature.hex(),
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(),
            algorithm = "Ed448",
        )

    
    @staticmethod
    def validate_signatures(commitment_values: list, identity_attributes: str, owner_public_key: str, issuer_signature: str, producer_signature: str) -> bool:

        attributes = dict(identity_attributes)
        issuer_signature = dict(issuer_signature)
        producer_signature = dict(producer_signature)
        owner_public_key = dict(owner_public_key)

        data_to_validate = (
            "".join(commitment_value for commitment_value in commitment_values) +
            "".join(label + value + mask for label, attr in attributes.items() for value, mask in attr.items())
            .join(owner_public_key["key"])
            .join(issuer_signature["signature_value"])
        ).encode()

        owner_public_key = Public_Key(
            load_pem_public_key(owner_public_key["key"].encode()),
            owner_public_key["algorithm"]
        )

        issuer_signature = Issuer_Signature(
            signature_value = issuer_signature["signature_value"],
            timestamp = issuer_signature["timestamp"],
            algorithm = issuer_signature["algorithm"],
            issuer_certificate = issuer_signature["issuer_certificate"]
        )

        try:
            is_issuer_valid = DCC.validate_signature(owner_public_key, issuer_signature, commitment_values)
            print("Issuer signature is " + ("valid" if is_issuer_valid else "invalid"))
            if not is_issuer_valid:
                raise ValueError("Issuer signature is invalid.")

            owner_public_key.key.verify(
                bytes.fromhex(producer_signature.signature_value),
                data_to_validate,
            )
            return True
        except Exception:
            return False

    def __repr__(self):
        # Convert identity attributes to a list of dictionaries
        attributes = dict()
        for attr in self.identity_attributes:
            attributes[attr.label] = {
                "value": attr.value,
                "mask": attr._pseudo_random_mask,
            }
        
        return json.dumps({
            "commitment_values": self.commitment_values,
            "attributes_digest_description": self.attributes_digest_description,
            "revealed_identity_attributes": attributes,
            "owner_public_key": {
                "key": self.owner_public_key.to_pem().decode(),
                "algorithm": self.owner_public_key.algorithm
            },
            "issuer_signature": asdict(self.issuer_signature),
            "producer_signature": asdict(self.producer_signature),
        }, indent=2)