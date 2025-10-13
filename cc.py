from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import os

def generate_signature(private_key, file_path):
    """Generates a digital signature for the data in a file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        signature = private_key.sign(
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except FileNotFoundError:
        print(f"File not found at: {file_path}")
        return None
    except Exception as e:
        print(f"An error occurred during signature generation: {e}")
        return None

def verify_signature(public_key, file_path, signature):
    """Verifies a digital signature against the data in a file."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        public_key.verify(
            signature,
            data,
            PSS(
                mgf=MGF1(hashes.SHA256()),
                salt_length=PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except FileNotFoundError:
        print(f"File not found at: {file_path}")
        return False
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"An error occurred during signature verification: {e}")
        return False

# Update the main part of the script to use the new functions and logic

# Define file paths for keys
private_key_path = 'private_key.pem'
public_key_path = 'public_key.pem'

private_key = None
public_key = None

# 1. Check if keys exist and load or generate them
if os.path.exists(private_key_path) and os.path.exists(public_key_path):
    print("Existing keys found. Loading keys...")
    try:
        # Load private key
        with open(private_key_path, 'rb') as f:
            private_pem_loaded = f.read()
        private_key = serialization.load_pem_private_key(
            private_pem_loaded,
            password=None,  # Assuming no encryption
            backend=default_backend()
        )

        # Load public key
        with open(public_key_path, 'rb') as f:
            public_pem_loaded = f.read()
        public_key = serialization.load_pem_public_key(
            public_pem_loaded,
            backend=default_backend()
        )
        print("Keys loaded successfully.")
    except Exception as e:
        print(f"Error loading keys: {e}")
        # If loading fails, we'll need to generate new keys
        private_key = None
        public_key = None
else:
    print("Key files not found or loading failed. Generating new keys...")

if private_key is None or public_key is None:
    try:
        # Generate a new key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Save the new keys
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            f.write(private_pem)

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_key_path, 'wb') as f:
            f.write(public_pem)

        print(f"New private key saved to {private_key_path}")
        print(f"New public key saved to {public_key_path}")

    except Exception as e:
        print(f"An error occurred during key generation and saving: {e}")
        # Exit if we can't generate keys
        exit()


# 2. Prompt user for file path
file_path = input("Enter the path to the file to be signed or verified: ")

# 3. Construct the expected signature file path
signature_file_path = file_path + '.sig'

# 4. Check if the signature file exists
if os.path.exists(signature_file_path):
    print(f"Signature file found for {file_path}. Attempting to verify...")
    # 7. If the signature file exists:
    try:
        # Load the signature from the file
        with open(signature_file_path, 'rb') as f:
            signature = f.read()
        print(f"Loaded Signature: {signature.hex()}") # Display loaded signature

        # Call the verify_signature function
        is_valid = verify_signature(public_key, file_path, signature)

        # Print verification result
        if is_valid:
            print("Signature is valid.")
        else:
            print("Signature is invalid.")
    except FileNotFoundError:
         # This case should ideally not happen if os.path.exists passed, but included for robustness
        print(f"Error: File to be verified not found at: {file_path}")
    except Exception as e:
        print(f"An error occurred during signature verification: {e}")

else:
    print(f"Signature file not found for {file_path}. Generating signature...")
    # 8. If the signature file does not exist:
    try:
        # Call the generate_signature function
        signature = generate_signature(private_key, file_path)

        if signature is not None:
            print(f"Generated Signature: {signature.hex()}") # Display generated signature
            # Save the generated signature to the constructed signature file path
            with open(signature_file_path, 'wb') as f:
                f.write(signature)
            print(f"Signature generated and saved to {signature_file_path}")
        else:
            print("Signature generation failed.")
    except FileNotFoundError:
        print(f"Error: File to be signed not found at: {file_path}")
    except Exception as e:
        print(f"An error occurred during signature generation and saving: {e}")
