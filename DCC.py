from dataclasses import dataclass, field
from cryptography.hazmat.primitives.hashes import Hash, SHA384


@dataclass
class Identity_attribute:
    label: str = ""
    value: str = ""
    _password: str = ""
    commitment_value: str = field(init=False)

    def __post_init__(self):
        hash = Hash(SHA384())
        hash.update((self.label + self._password).encode())
        pseudo_random_mask = hash.finalize()
        hash = Hash(SHA384())
        hash.update(self.label.encode() + self.value.encode() + pseudo_random_mask)
        self.commitment_value = hash.finalize().hex()

@dataclass
class Public_key:
    key: str = ""
    algorithm: str = ""

@dataclass
class Issuer_signature:
    signature_value: str = ""
    timestamp: str = ""
    algorithm: str = ""
    certificate: str = ""

@dataclass
class DCC:
    identity_attributes: set = field(default_factory=set())
    attributes_digest_description: str = "SHA-384 for pseudo-random mask and SHA-384 for commitment value"
    public_key: Public_key = field(default_factory=Public_key)
    issuer_signature: Issuer_signature = field(default_factory=Issuer_signature)

