import sys
import time

import dns.query

# --- NEW: dnspython imports for RFC 2136 ---
import dns.tsigkeyring
import dns.update
import dns.zone
import josepy as jose

# Import ACME classes from the documentation
from acme import challenges, client, crypto_util, messages
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --- Configuration ---
# Use Let's Encrypt's staging directory for testing
ACME_DIRECTORY_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"
# ACME_DIRECTORY_URL = 'https://acme-v02.api.letsencrypt.org/directory' # Production
USER_EMAIL = "orlf00@vse.cz"
DOMAIN_TO_VALIDATE = "ptz1.kme.vse.cz"
NSUPDATE_KEY_PATH = "/Users/filiporlicky/update.key"
NSUPDATE_SERVER = "146.102.42.42"
NSUPDATE_ZONE= "_le.vse.cz"
ALIAS_DOMAIN = "ptz1.kme._le.vse.cz"

# --- Key Generation (Prerequisite) ---
# You must securely generate and store these keys.
# This is just a demonstration of key generation.

def generate_rsa_key():
    """Generates a 2048-bit RSA key and wraps it in jose.JWK."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, jose.jwk.JWK.load(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))

def generate_pem_from_key(key):
    """Generates PEM-formatted bytes from a private key."""
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

print("Generating account key and domain key...")
ACCOUNT_PRIVATE_KEY, ACCOUNT_JWK = generate_rsa_key()
DOMAIN_PRIVATE_KEY, _ = generate_rsa_key()
DOMAIN_PRIVATE_KEY_PEM = generate_pem_from_key(DOMAIN_PRIVATE_KEY)

# --- DNS Provider Hook (ACTION REQUIRED) ---
# This is the most critical part you must implement.
# You need to write a function that uses your DNS provider's API
# to create and delete TXT records.

def create_dns_txt_record(ALIAS_DOMAIN, validation_value):
    """Performs a dynamic DNS update (RFC 2136) to create a TXT record.

    Args:
        validation_domain_name (str): The FQDN for the TXT record (e.g., '_acme-challenge.example.com.')
        validation_value (str): The string value to put in the TXT record.

    Returns:
        bool: True on success, False on failure.
    """
    print(f"Attempting to create TXT record for: {ALIAS_DOMAIN}")
    try:
        # Load the TSIG key from the file
        keyring = dns.tsigkeyring.from_file(NSUPDATE_KEY_PATH)

        # Get the key name from the keyring (assumes only one key in the file)
        key_name = list(keyring.keys())[0]

        # Create an update object for the specified zone
        update = dns.update.Update(NSUPDATE_ZONE, keyring=keyring, keyname=key_name)

        # Add the TXT record (300-second TTL is common for challenges)
        # Note: The validation_value must be bytes or a string that can be
        # encoded. For ACME, it's typically a single string.
        print(f'  Adding: {ALIAS_DOMAIN} 300 IN TXT "{validation_value}"')
        update.add(ALIAS_DOMAIN, 300, "TXT", validation_value)

        # Send the update to the server
        response = dns.query.tcp(update, NSUPDATE_SERVER)
        print("DNS update sent successfully.")

        # It's crucial to wait for DNS propagation
        print("Waiting 60 seconds for DNS propagation...")
        time.sleep(60)
        print("Propagation wait complete.")
        return True

    except FileNotFoundError:
        print(f"ERROR: TSIG key file not found at '{NSUPDATE_KEY_PATH}'", file=sys.stderr)
        return False
    except dns.exception.DNSException as e:
        print(f"ERROR: DNS update failed: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}", file=sys.stderr)
        return False


def delete_dns_txt_record(ALIAS_DOMAIN, validation_value):
    """Performs a dynamic DNS update (RFC 2136) to delete a specific TXT record.

    Args:
        validation_domain_name (str): The FQDN of the TXT record to delete.
        validation_value (str): The specific value of the TXT record to delete.
                                This ensures we only delete the exact record we added.

    Returns:
        bool: True on success, False on failure.
    """
    print(f"Attempting to delete TXT record for: {ALIAS_DOMAIN}")
    try:
        # Load the TSIG key from the file
        keyring = dns.tsigkeyring.from_file(NSUPDATE_KEY_PATH)

        # Get the key name from the keyring
        key_name = list(keyring.keys())[0]

        # Create an update object
        update = dns.update.Update(NSUPDATE_ZONE, keyring=keyring, keyname=key_name)

        # Delete the specific TXT record that matches the name and value
        print(f'  Deleting: {ALIAS_DOMAIN} IN TXT "{validation_value}"')
        update.delete(ALIAS_DOMAIN, "TXT", validation_value)

        # Send the update to the server
        response = dns.query.tcp(update, NSUPDATE_SERVER)
        print("DNS delete request sent successfully.")

        # Short wait for the server to process the deletion
        print("Waiting 10 seconds for deletion to process...")
        time.sleep(10)
        return True

    except FileNotFoundError:
        print(f"ERROR: TSIG key file not found at '{NSUPDATE_KEY_PATH}'", file=sys.stderr)
        return False
    except dns.exception.DNSException as e:
        print(f"ERROR: DNS delete failed: {e}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: An unexpected error occurred: {e}", file=sys.stderr)
        return False

# --- Main ACME Workflow ---
def main_workflow():

    # --- (Account Creation) ---
    print("\n--- 1. Account Creation ---")

    # Initialize the ClientNetwork

    net = client.ClientNetwork(
        key=ACCOUNT_JWK,
        user_agent="my-acme-python-client",
    )

    # Get the directory

    directory = client.ClientV2.get_directory(ACME_DIRECTORY_URL, net)

    # Initialize the ClientV2

    acme_client = client.ClientV2(directory, net)

    try:
        # Create a NewRegistration object with contact info and ToS agreement

        new_reg = messages.NewRegistration.from_data(
            email=USER_EMAIL,
            terms_of_service_agreed=True,
        )
        # Register the account
        regr = acme_client.new_account(new_reg)
        print(f"Successfully registered new account: {regr.uri}")
    except client.errors.ConflictError as e:
        # If account already exists, query for it

        print("Account already exists. Querying for registration...")
        regr = acme_client.query_registration(
            messages.RegistrationResource(uri=e.location),
        )
        print(f"Loaded existing account: {regr.uri}")

    # --- (Certificate Actions) ---
    print("\n--- 2. Certificate Actions ---")

    # Create the CSR

    print("Creating CSR...")
    csr_pem = crypto_util.make_csr(
        private_key_pem=DOMAIN_PRIVATE_KEY_PEM,
        domains=[DOMAIN_TO_VALIDATE],
    )

    # --- Issue Certificate (Order and Challenge) ---

    # 1. Request a new order

    print("Requesting new order...")
    orderr = acme_client.new_order(csr_pem)

    # 2. Get the authorizations

    authzr_resource = orderr.authorizations[0] # Assuming one domain

    # 3. Find the DNS-01 challenge

    dns_challenge_body = None
    for chall in authzr_resource.body.challenges:
        if isinstance(chall.chall, challenges.DNS01):
            dns_challenge_body = chall
            break

    if not dns_challenge_body:
        raise Exception("No DNS-01 challenge found.")

    dns_challenge = dns_challenge_body.chall
    print("Found DNS-01 challenge.")

    # 4. Get DNS validation details

    validation_value = dns_challenge.validation(ACCOUNT_JWK)

    validation_domain = dns_challenge.validation_domain_name(DOMAIN_TO_VALIDATE)

    # 5. (External Step) Update DNS
    create_dns_txt_record(ALIAS_DOMAIN, validation_value)

    # 6. Answer the challenge
    print("Notifying server to check challenge...")

    dns_response = challenges.DNS01Response()

    acme_client.answer_challenge(dns_challenge_body, dns_response)

    # 7. Poll and Finalize
    print("Polling for authorization and finalizing order...")
    try:
        # poll_and_finalize handles polling for authz and cert status

        final_orderr = acme_client.poll_and_finalize(orderr)
    except Exception as e:
        print(f"Error finalizing order: {e}")
        return
    finally:
        # 8. (External Step) Cleanup DNS
        delete_dns_txt_record(ALIAS_DOMAIN, validation_value)

    # 9. Download Certificate

    print("\n--- Certificate Issued! ---")
    print(final_orderr.fullchain_pem)
    fullchain_pem = final_orderr.fullchain_pem

    # --- Renew Certificate ---
    # Renewal is just re-running the issuance workflow.
    # You can check if it's time to renew.
"""
    renewal_suggestion = acme_client.renewal_time(fullchain_pem.encode())
    print(f"\nRenewal suggestion: {renewal_suggestion}")
    # You would trigger the issuance workflow again if it's time.
"""
"""
    # --- Revoke Certificate ---
    print("\n--- 3. Revoke Certificate ---")
    # Load the certificate from the PEM string
    cert_obj = x509.load_pem_x509_certificate(fullchain_pem.encode())


    try:
        acme_client.revoke(cert_obj, rsn=0) # rsn 0 = unspecified
        print("Certificate successfully revoked.")
    except Exception as e:
        print(f"Error revoking certificate: {e}")
"""
"""
    # --- (Account Update Actions) ---
    print("\n--- 4. Account Update Actions ---")

    # Change contact information
    print("Updating account contact info...")
    new_contact_email = "new-email@example.com"

    updated_reg_body = messages.Registration.from_data(email=new_contact_email)

    regr = acme_client.update_registration(regr, updated_reg_body)
    print(f"Account contact updated: {regr.body.emails}") # [cite: 327]

    # Deactivate Account
    print("Deactivating account...")

    deactivated_regr = acme_client.deactivate_registration(regr)
    print(f"Account deactivated: {deactivated_regr.uri}")
"""

if __name__ == "__main__":
    # Note: This is a conceptual script.
    # Running it will make live requests to the ACME staging server
    # and will require you to manually update your DNS records.

     main_workflow()
