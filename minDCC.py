from dataclasses import dataclass, field, asdict
from DCC import Public_Key, Signature, Issuer_Signature, Identity_Attribute, DCC

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import Hash, SHA384, SHA3_512
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import json
import datetime

@dataclass
class minDCC:
    commitment_values: list = field(default_factory=list)
    attributes_digest_description: str = "SHA-3_512 for pseudo-random mask and SHA-384 for commitment values"
    identity_attributes: set = field(default_factory=set)
    owner_public_key: Public_Key = field(default_factory=Public_Key)
    owner_private_key: Ed25519PrivateKey = None
    issuer_signature: Issuer_Signature = field(default_factory=Issuer_Signature)
    producer_signature: Signature = field(init=False)

    def __post_init__(self):
        if self.owner_private_key is None:
            raise ValueError("Owner private key must be provided.")
        self.sign_attributes(self.owner_private_key)

    def sign_attributes(self, private_key: Ed25519PrivateKey):
        data_to_sign = (
            "".join(commitment_value for commitment_value in self.commitment_values)
            .join(identity_attribute for identity_attribute in self.identity_attributes)
            .join(self.owner_public_key)
            .join(self.issuer_signature)
        ).encode()

        signature = private_key.sign(
            data_to_sign
        )

        self.producer_signature = Signature(
            signature_value=signature.hex(),
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(),
            algorithm = "Ed25519",
        )

    
    @staticmethod
    def validate_signature(commitment_values: list, identity_attributes: set[Identity_Attribute], owner_public_key: Public_Key, issuer_signature: Issuer_Signature, producer_signature: Signature):
        data_to_validate = (
            "".join(commitment_value for commitment_value in commitment_values)
            .join(identity_attribute for identity_attribute in identity_attributes)
            .join(owner_public_key)
            .join(issuer_signature)
        ).encode()

        try:
            DCC.validate_signature(owner_public_key, issuer_signature, commitment_values)
            owner_public_key.key.verify(
                bytes.fromhex(producer_signature.signature_value),
                data_to_validate,
            )
            return True
        except Exception:
            return False

    def __repr__(self):
        # Convert identity attributes to a list of dictionaries
        attributes = [
            {"label": attr.label, "value": attr.value, "commitment_value": attr.commitment_value}
            for attr in self.identity_attributes
        ]

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