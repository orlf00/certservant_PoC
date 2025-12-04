
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import dns.query
import dns.tsigkeyring
import dns.update
import josepy as jose
from acme import challenges, client, crypto_util, errors, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from devices import Device

CERT_PKEY_BITS = 2048
ACC_KEY_BITS = 2048
USER_AGENT= "CertServant/1.0"



def new_csr_comp(domain_name, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        pkey = rsa.generate_private_key(public_exponent=65537, key_size=CERT_PKEY_BITS)
        pkey_pem = pkey.private_bytes(encoding=serialization.Encoding.PEM,
                                      format=serialization.PrivateFormat.PKCS8,
                                      encryption_algorithm=serialization.NoEncryption())

    csr_pem = crypto_util.make_csr(pkey_pem, [domain_name])
    return pkey_pem, csr_pem

def select_dns01_chall(orderr):
    """Extract authorization resource from within order resource."""
    # Authorization Resource: authz.
    # This object holds the offered challenges by the server and their status.
    authz_list = orderr.authorizations

    for authz in authz_list:
        # Choosing challenge.
        # authz.body.challenges is a set of ChallengeBody objects.
        for i in authz.body.challenges:
            # Find the supported challenge.
            if isinstance(i.chall, challenges.DNS01):
                return i
    raise Exception("DNS-01 challenge was not offered by the CA server.")

def dns_add_record(validation, dev: Device):
    keyring = dns.tsigkeyring.from_text(
        {
            f"{dev.nsupdate_name}": f"{dev.nsupdate_key}",
        },
    )
    update = dns.update.UpdateMessage(f"{dev.nsupdate_zone}", keyring=keyring)
    update.replace(f"_acme-challenge.{dev.nsupdate_subdomain}", 60, "TXT", validation)
    response = dns.query.tcp(update, f"{dev.nsupdate_server}")
    print("sleeping 3 seconds to let DNS propagate...")
    sleep(3)
    return True

def dns_remove_record(dev: Device):
    keyring = dns.tsigkeyring.from_text(
        {
            f"{dev.nsupdate_name}": f"{dev.nsupdate_key}",
        },
    )
    update = dns.update.UpdateMessage(f"{dev.nsupdate_zone}", keyring=keyring)
    update.delete(f"_acme-challenge.{dev.nsupdate_subdomain}", "TXT")
    response = dns.query.tcp(update, f"{dev.nsupdate_server}")
    print("DNS record removed.")

def create_files(leaf, pkey, fullchain, base, dev: Device):
    base = Path(base) / dev.domain

    base.mkdir(parents=True, exist_ok=True)

    (base / "cert.pem").write_text(leaf, encoding="utf-8")
    (base / "privkey.key").write_text(pkey, encoding="utf-8")
    (base / "fullchain.pem").write_text(fullchain, encoding="utf-8")
    (base / "ssl.pem").write_text(pkey + leaf, encoding="utf-8")




def generatecert(dev: Device, base: str):

    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=ACC_KEY_BITS,
                                     backend=default_backend()))
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(dev.renew_server, net)
    client_acme = client.ClientV2(directory, net=net)

    if dev.eab_key is not None and dev.eab_kid is not None:
        eab_creds = messages.ExternalAccountBinding.from_data(
            account_public_key=acc_key, kid=dev.eab_kid, hmac_key=dev.eab_key, directory=directory)
        regr = client_acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True, external_account_binding=eab_creds))
    else:
        regr = client_acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))

    pkey_pem, csr_pem = new_csr_comp(dev.domain)

    orderr = client_acme.new_order(csr_pem)
    challb= select_dns01_chall(orderr)
    response, validation = challb.response_and_validation(client_acme.net.key)
    authz_ref = orderr.authorizations[0]
    authz = authz_ref if hasattr(authz_ref, "body") else client_acme._post_as_get(authz_ref)
    status = authz.body.status.name

    added_dns = False
    if status.upper() == "PENDING":
        ready_to_validate = dns_add_record(validation, dev)
        if ready_to_validate:
            added_dns = True
            challenge_resource = client_acme.answer_challenge(challb, response)
    deadline = datetime.now() + timedelta(seconds=180)
    try:
        finalized_order = client_acme.poll_and_finalize(orderr, deadline)
        fullchain_pem = finalized_order.fullchain_pem
        leaf_pem=fullchain_pem.split("-----END CERTIFICATE-----\n")[0] + "-----END CERTIFICATE-----\n"
        pkey_str = pkey_pem.decode("utf-8")
        create_files(leaf_pem,pkey_str,fullchain_pem,base,dev)
        print(leaf_pem)
        print(pkey_str)
        print(fullchain_pem)
    except errors.ValidationError as e:
        print("Validation error:", e)
    finally:
        if added_dns:
            dns_remove_record(dev)

"""
def generatecert_eab(dev: Device):

    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=ACC_KEY_BITS,
                                     backend=default_backend()))
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(dev.renew_server, net)
    client_acme = client.ClientV2(directory, net=net)


    # Terms of Service URL is in client_acme.directory.meta.terms_of_service
    # Registration Resource: regr
    eab_creds= messages.ExternalAccountBinding.from_data(account_public_key=acc_key,kid=dev.eab_kid,hmac_key=dev.eab_key,directory=directory)
    regr = client_acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True, external_account_binding=eab_creds))

    pkey_pem, csr_pem = new_csr_comp(dev.domain)

    orderr = client_acme.new_order(csr_pem)
    challb= select_dns01_chall(orderr)
    response, validation = challb.response_and_validation(client_acme.net.key)
    authz_ref = orderr.authorizations[0]  # může to už být AuthorizationResource
    authz = authz_ref if hasattr(authz_ref, "body") else client_acme._post_as_get(authz_ref)
    status = authz.body.status.name

    added_dns = False
    if status.upper() == "PENDING":
        ready_to_validate = dns_add_record(validation)
        if ready_to_validate:
            added_dns = True
            challenge_resource = client_acme.answer_challenge(challb, response)
    deadline = datetime.now() + timedelta(seconds=180)
    try:
        finalized_order = client_acme.poll_and_finalize(orderr, deadline)
        fullchain_pem = finalized_order.fullchain_pem
        pkey_str = pkey_pem.decode("utf-8")
        print(pkey_str)
        print(fullchain_pem)
    except errors.ValidationError as e:
        print("Validation error:", e)
    finally:
        if added_dns:
            dns_remove_record()
"""




if __name__ == "__main__":
    generatecert()
