from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
import os


# Helper method to convert bytes to strings
def utf8(s: bytes):
    return str(s, 'utf-8')


# 1. Obtain copy of old_private_key from old_private_key.pem file.
def load_private_key(file_name):
    with open(file_name, 'rb') as file:
        private_key_data = file.read()
        private_key = serialization.load_pem_private_key(
            private_key_data, password=None, backend=default_backend())
    return private_key


# 2. Obtain copy of new_public_key from new_public_key.pem file.
def load_public_key(file_name):
    with open(file_name, 'rb') as file:
        public_key_data = file.read()
        public_key = serialization.load_pem_public_key(
            public_key_data, backend=default_backend())
    return public_key


# 3. Use the old_private_key to decrypt ONE bin file in the user_profiles directory.
# files in the user_profiles directory are Bin files.
# the file format is aaron_.diaz.bin, aaron_flores.bin, adammartin.bin, etc.
def decrypt_profile(encrypted_profile, key):
    decrypted_profile = key.decrypt(
        base64.b64decode(encrypted_profile),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_profile


# 4. Use the new_public_key to encrypt the file.
def encrypt_profile(profile, key):
    encrypted_profile = base64.b64encode(key.encrypt(
        profile,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ))
    return encrypted_profile


# 5. Save the newly encrypted file to a directory named new_user_profiles.
def write_encrypted_profile_to_file(file_name, encrypted_profile):
    with open(file_name, 'wb') as file:
        file.write(encrypted_profile)


def main():
    # Load the private key
    private_key = load_private_key('old_private_key.pem')

    # Load the public key
    public_key = load_public_key('new_public_key.pem')

    # Open the encrypted bin file from the user_profiles directory and print to screen
    with open('user_profiles/aaron_diaz.bin', 'rb') as file:
        encrypted_data = file.read()

    # Decrypt the profile with the private key
    decrypted_profile = decrypt_profile(encrypted_data, private_key)
    print(f"Decrypted Profile: {utf8(decrypted_profile)}")
    print(f"\nEncrypted with new key: {encrypt_profile(decrypted_profile, public_key)}")

    # Encrypt the profile with the public key and save to new_user_profiles directory
    os.makedirs("new_user_profiles", exist_ok=True)
    encrypted_profile = encrypt_profile(decrypted_profile, public_key)
    write_encrypted_profile_to_file('new_user_profiles/aaron_diaz.bin', encrypted_profile)


if __name__ == "__main__":
    main()
