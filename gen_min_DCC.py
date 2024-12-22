import argparse
import json
from minDCC import minDCC
from DCC import generate_identity_attributes

example_dcc = {
  "identity_attributes": [
    {
      "label": "nome",
      "value": "Marcolino",
      "commitment_value": "fab5f52bcfbfd50c73066177bc53c5a8695c4ce8c08e585b151c862db8165b4900c2b478d1fd37c5b05bd9e263c96301"
    },
    {
      "label": "data_nascimento",
      "value": "24/02/1999",
      "commitment_value": "afa3e4b1b1328b48259ac16a5162925ad2161511ff1b025f86df9baf300830bbde14026eca579c11150f8bbccc050574"
    }
  ],
  "attributes_digest_description": "SHA-3_512 for pseudo-random mask and SHA-384 for commitment value",
  "owner_public_key": {
    "key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmuaTulsyts1j2aeoKHH3\n9CbmM61J85ilYrsJsnPA5oQcKkzv3mEqqCpLs+Ey6SJAjoWcZMW5EbKaEzcVd1Ph\ncY5tIiUgWUsH+D0/6HCCLbtf5XRLOVdPVYaCe6g4E4kMywnMYG72/36zfHquCFQx\n5MPvYPPxHLWYeFV1K3097EHDC2B6YZrhaHeTBAbOhfgBrRd7vsxwyPNzpS7kwhlp\npE0vbzRLsNeCTN9pcts77Rcca8NvzSz6xHbm6MbTbtro9S6UZ9I7mGbhvdzXaWGq\nxgN2aO5YDAjIv8psVPi53inkUuRipS036EDdxp9FGrHjtvqIrLJNXjZQILeEglvx\nCQIDAQAB\n-----END PUBLIC KEY-----\n",
    "algorithm": "RSA-4096"
  },
  "issuer_signature": {
    "signature_value": "902db5a83bbf08c792971e57d64a43ad60b32006a330d801df626865d9d5947b7d53eb437a5abfff87ee4f7f11701044d38ac4760d8ff801c478f3e505e26e4725e274f2c111a5e8bb2d4d9d3e8864e438396966133e1ba10d77508af8abc370d2352eaa41db3047af00bb6f69afea88f47f533a70a71fec4dd8bcaba43da7612e2ddc61a7df02aecb47766ff1846d30894d94feab5348f6fefe344b36dc77bf1d40cd5a9948d5c938e9bed30f7298f4c92d26a7f4165b0f182a7776a92168f5041e19a7158b64e30b92c42ef3d7b7e19d5d74dd44f92781651ddc5dab7952876b2a238d81b954e681f69e41429e1fa07f2e18806413c336e448d7f484f9e2a6dce044516e84688ed1b2339d061a046a682ce94d013c10934bcd14c983377b1338fc1e8364d7d1a981d3cf5675dc1d1f68956696020868183789ba76d123a1b6a0737244f42e87bda3922da9823b9b426c81f2b209541cbedda30201e713dc968133a093e6065c1e95f89600d3635ae26b991103b2ce6d1ca7bf7870544e6cefd95b71a9c4673129d5a2db155550fc4e33d4039c816eabe2a1af9d73f3aa6eaf842b0f52ce31596010e11cea8454c6fb1f19319d066243e533a43cddae7f2bebd8253169d5cdd6036ce4e5bbeb908f77b5ff061582e3bb38021caef08ab6bff1ffb9d11e83fd2bf775f977d986286dc26fe6eeb0d9a477e3e45c249b06aaf436",
    "timestamp": "2024-12-22T17:35:12.219782",
    "algorithm": "Ed448",
    "issuer_certificate": "-----BEGIN CERTIFICATE-----\nMIIFQjCCAyqgAwIBAgIUSYVKzJKCYK0W8oB4jroaNuzcjTMwDQYJKoZIhvcNAQEL\nBQAwWzELMAkGA1UEBhMCUFQxDzANBgNVBAgMBkF2ZWlybzERMA8GA1UEBwwIRXNn\ndWVpcmExEjAQBgNVBAoMCUNBX0lTU1VFUjEUMBIGA1UEAwwLZXhhbXBsZS5jb20w\nHhcNMjQxMjIyMTczNTEyWhcNMjUwMTAxMTczNTEyWjBbMQswCQYDVQQGEwJQVDEP\nMA0GA1UECAwGQXZlaXJvMREwDwYDVQQHDAhFc2d1ZWlyYTESMBAGA1UECgwJQ0Ff\nSVNTVUVSMRQwEgYDVQQDDAtleGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQAD\nggIPADCCAgoCggIBALyXM+YlvCirEpIeGqzQfoKF0nt0hLl9EwENW9KXl9woyZ81\neIwBr1c1SP7O4OBcghP3+Aih+fLBr4uFoAvESSqTGoCLYjW5vfR/Gau1ubhtxnPn\n6vjEQ2G5V4yMTjt7NHGm6esmSEyuH0G4wy9WsUg5QVGBGb4iGQ4s2TZKrUJtt00+\nKgGflwlOko3+nwe+h5ovyi3VZF91FqszCPk+aFkI4AANYHVuHXVS6Lq28uqF6ccN\nqDn350ecb84k0Yv0GCXNWA6kSM8ZDehaHyCt46tnIIaYJ9Ebv8HDfX8XY1FtXe5e\nAWa+CARc+YWecH6HOzJRIyMVWcYaF2c8hQi72KhVv1GkK+pmCTgZGMZlH9vYGQ0w\nFsPj4QoLaNWOj8CyUhUhPK87jFuf39rS1okCsuJCgKiTLBYABeguUTtWdfWh+mY7\n5CfKazkiGufVmO5LnNz1+N4H8FN+AWpXngB9XirOvy502Oqte3QW06D5qaaX1Xtr\nHqwRSx2o9hmetOmgCJY2K6EREqCgyp3nT1cDEthDEwMpFXbPeYwhZFdvLRhoQIbO\nUoxHP9WResd8LYutsZ3xkgK3jJvokhlVzO+JtOFqgFUJIZ4nqz3zvQFuxdf09yye\nQqSEehpik9wriBcQPA1yvdlK1/xkOv47uHuVXTqYry/9egSiD57YOfhDggRFAgMB\nAAEwDQYJKoZIhvcNAQELBQADggIBAH0wxuUsWK5+ztu64HTgeof9S8I41jovE7DB\nHuJtuRlQLLqBUSVkfEAyRGXC7rs4dTq2fcsNYlO6BlVcHKjPvT/NUwCc9xUE59d6\nNuMypOpQ8qTzLy/Ewy9uP+Zn7Zl8LFm9SPmX2O/Sj8OzYxVv9bdAHevJP794jdx+\nrhHzVvT+lb6E69QaEbs+hr1l49xxWGhxkmQmDqM3zBdt8liy8zGDkQlFfVZBrlJR\nkIlqaJ4og+FilBIdLtg5F8Ozt79LpZ46HskiFVJepUj8Ap5Vd52BnSRaGWDuytMh\n5k52XL3C9uNt/fcMf0/rY/jhgUaNZd4hu9NMcBiqpb3HdsnzDwI0BVXLFs0xvkiC\nciupdQk8I9+6tVyPhsf6swneUe/r5xXFVunKKnxdJ9OHx65KguPrTIu+s+qWtCa1\ndC8hKXfq8p6lJaLaRLS7mpR0i0d30LIhEJuFn+hE9LlMZvSKE4tMZzZj4gU5CVai\nXp+A93fJ913EumtMKvCv0tz8wNT3x3ROLGyjG8WLEDDlvn90BJfSHmb2mPsrR7Vc\nal5KkUE8euXUw4Qx7C6sko8ft9PG0srGiyhLim1SbxEyn/3kXxrnPHR8AEnoGf5a\nexXTNg8SHuwK/WYGp8IDqdrJ9RhM09zBeKZTE1EeS4RS2U7R0apnelqMbxv4hlPK\nogvNDkxw\n-----END CERTIFICATE-----\n"
  }
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dcc_path", type=str)
    parser.add_argument("private_key_path", type=str)

    args = parser.parse_args()

    try:
        with open(args.dcc_path, "r") as dcc_file:
            example_dcc = json.load(dcc_file)
    except Exception as e:
        print(f"Error loading DCC document: {e}")
        return

    try:
        with open(args.private_key_path, "r") as key_file:
            private_key = key_file.read()
    except Exception as e:
        print(f"Error loading private key: {e}")
        return

    try:

      commitment_values = [attr["commitment_value"] for attr in example_dcc["identity_attributes"]]
      digest_description = example_dcc["attributes_digest_description"]
      owner_public_key = example_dcc["owner_public_key"]
      issuer_signature = example_dcc["issuer_signature"]

      name_attribute = example_dcc["identity_attributes"][0]
      revealed_attributes = dict()
      revealed_attributes[name_attribute["label"]] = name_attribute["value"]

      password = input("Password: ")
      identity_attributes = generate_identity_attributes(password, revealed_attributes)

      min_dcc = minDCC(
          commitment_values=commitment_values,
          attributes_digest_description=digest_description,
          owner_public_key=owner_public_key,
          issuer_signature=issuer_signature,
          identity_attributes=identity_attributes
      )

      print(min_dcc)
    
    except Exception as e:
        print(f"Error generating minDCC: {e}")

if __name__ == "__main__":
  main()