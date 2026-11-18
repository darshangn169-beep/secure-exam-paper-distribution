"""
keygen.py
---------
Run this ONCE before starting the app for the first time.
Generates RSA key pairs for:
  - the Admin (Question Paper Setter) -> used to SIGN papers
  - each Exam Center                  -> used to RECEIVE the encrypted AES key

In a real deployment each party would generate their own keypair and only
share the PUBLIC key. Here we generate all of them centrally purely to make
the demo runnable end-to-end on one machine.
"""

import os
from crypto_utils import generate_rsa_keypair

KEYS_DIR = "keys"

ENTITIES = ["admin", "center1", "center2"]


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)

    for entity in ENTITIES:
        priv_path = os.path.join(KEYS_DIR, f"{entity}_private.pem")
        pub_path = os.path.join(KEYS_DIR, f"{entity}_public.pem")

        if os.path.exists(priv_path) and os.path.exists(pub_path):
            print(f"[skip] Keys already exist for '{entity}'")
            continue

        private_pem, public_pem = generate_rsa_keypair()

        with open(priv_path, "wb") as f:
            f.write(private_pem)
        with open(pub_path, "wb") as f:
            f.write(public_pem)

        print(f"[ok] Generated RSA-2048 keypair for '{entity}'")

    print("\nAll keys ready in ./keys/")


if __name__ == "__main__":
    main()
