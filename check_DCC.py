import argparse
import json
from minDCC import minDCC

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("min_dcc_path", type=str)

    args = parser.parse_args()

    try:
        with open(args.min_dcc_path, "r") as dcc_file:
            min_dcc = json.load(dcc_file)
    except Exception as e:
        print(f"Error loading DCC document: {e}")
        return

    is_valid = minDCC.validate_signatures(
        commitment_values=min_dcc["commitment_values"],
        identity_attributes=min_dcc["revealed_identity_attributes"],
        owner_public_key=min_dcc["owner_public_key"],
        issuer_signature=min_dcc["issuer_signature"],
        producer_signature=min_dcc["producer_signature"]
    )

    if is_valid:
        print("minDCC is valid")
    else:
        print("minDCC is invalid")


if __name__ == "__main__":
  main()
