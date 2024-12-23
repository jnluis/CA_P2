import argparse
import json
from minDCC import minDCC
from DCC import generate_identity_attributes, Public_Key, Issuer_Signature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def main():
    parser = argparse.ArgumentParser(
        description="Process a DCC document and optionally sign it using a private key or a CC from the card reader."
    )
    parser.add_argument(
        "dcc_path",
        type=str,
        help="Path to the DCC document (required)."
    )
    parser.add_argument(
        "private_key_path",
        nargs="?",
        help=(
            "Optional path to the private key for signing. "
            "If not provided, the system will attempt to use a card reader for signing."
        ),
        default=None
    )

    args = parser.parse_args()

    if args.private_key_path:
        print(f"Using private key from: {args.private_key_path}")
    else:
        print("No private key path provided. Attempting to use card reader for signing.")


    try:
        with open(args.dcc_path, "r") as dcc_file:
            dcc_document = json.load(dcc_file)
    except Exception as e:
        print(f"Error loading DCC document: {e}")
        return

    if args.private_key_path is not None:
        try:
            with open(args.private_key_path, "r") as key_file:
                owner_private_key = key_file.read()
        except Exception as e:
            print(f"Error loading private key: {e}")
            return
    else:
        owner_private_key = None

    try:

      commitment_values = [attr["commitment_value"] for attr in dcc_document["identity_attributes"]]
      digest_description = dcc_document["attributes_digest_description"]
      owner_public_key = dcc_document["owner_public_key"]
      issuer_signature = dcc_document["issuer_signature"]
      
      print("The attributes in the DCC are:")
      for attribute in dcc_document["identity_attributes"]:
        print(attribute["label"])

      print()

      lables_of_attributes_to_reveal = (input("Input the attributes you want to reveal, seperated by commas, and press enter: ")).strip().replace(" ", "").split(",")

      revealed_attributes = dict()
      for attribute in dcc_document["identity_attributes"]:
        label = attribute["label"]
        if label in lables_of_attributes_to_reveal:
          revealed_attributes[label] = attribute["value"]

      password = input("Password: ")
      identity_attributes = generate_identity_attributes(password, revealed_attributes)

      min_dcc = minDCC(
          commitment_values=commitment_values,
          attributes_digest_description=digest_description,
          identity_attributes=identity_attributes,
          owner_public_key=Public_Key(load_pem_public_key(owner_public_key["key"].encode()), owner_public_key["algorithm"]),
          owner_private_key=owner_private_key,
          issuer_signature=Issuer_Signature(issuer_signature["signature_value"], issuer_signature["timestamp"], issuer_signature["algorithm"], issuer_certificate=issuer_signature["issuer_certificate"])
      )
      
      with open("min_DCC.json", "w") as f:
          f.write(min_dcc.__repr__())
    
    except Exception as e:
        print(f"Error generating minDCC: {e}")

if __name__ == "__main__":
  main()