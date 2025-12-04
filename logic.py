import asyncio
import os
from datetime import datetime, timedelta
from pathlib import Path
from time import sleep

import josepy as jose
from acme import client, errors, messages
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from dotenv import load_dotenv

from devices import Device
from helpers import (
    check_cert_file_serial,
    create_files,
    dns_add_record,
    dns_remove_record,
    domain_exists,
    ilofish_csr,
    ilofish_deploy,
    load_devices,
    new_csr_comp,
    refresh_cert_info,
    save_devices,
    select_dns01_chall,
    upload_cert_to_device,
)

load_dotenv()
ACC_KEY_BITS = os.getenv("ACC_KEY_BITS")
USER_AGENT= os.getenv("USER_AGENT")

def add_device(dev: Device, path: str) -> str | None:
    """Adds a new device if the domain does not already exist."""
    if domain_exists(path, dev.domain):
        return "Zařízení s touto doménou již existuje."
    devices = load_devices(path)
    dev.id = (max((d.id or 0) for d in devices) + 1) if devices else 1
    refresh_cert_info(dev)
    devices.append(dev)
    save_devices(path, devices)
    return None

def generatecert(dev: Device, base: Path):
    """Generate a certificate for the given device."""
    acc_key = jose.JWKRSA(
        key=rsa.generate_private_key(public_exponent=65537,
                                     key_size=2048,
                                     backend=default_backend()))
    net = client.ClientNetwork(acc_key, user_agent=USER_AGENT)
    directory = client.ClientV2.get_directory(dev.renew_server, net)
    client_acme = client.ClientV2(directory, net=net)

    if dev.eab_key is not None and dev.eab_kid is not None:
        eab_creds = messages.ExternalAccountBinding.from_data(
            account_public_key=acc_key, kid=dev.eab_kid, hmac_key=dev.eab_key, directory=directory)
        regr = client_acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True,
                                                                          external_account_binding=eab_creds))
    else:
        regr = client_acme.new_account(messages.NewRegistration.from_data(terms_of_service_agreed=True))
    if dev.redfish:
        csr_pem = ilofish_csr(dev).encode("utf-8")
    else:
        pkey_pem, csr_pem = new_csr_comp(dev.domain, dev.keytype)

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
        intermediate_pem = fullchain_pem
        if dev.redfish:
            create_files(leaf_pem, None, fullchain_pem, intermediate_pem, base, dev)
            ilofish_deploy(intermediate_pem, dev)

        else:
            pkey_str= pkey_pem.decode("utf-8")
            create_files(leaf_pem, pkey_str, fullchain_pem, intermediate_pem, base, dev)
        timestamp = datetime.now().isoformat()
        dev.last_renew = timestamp
        local_cert_sn = check_cert_file_serial(leaf_pem)
        dev.local_sn = local_cert_sn


    except errors.ValidationError as e:
        print("Validation error:", e)
    finally:
        if added_dns:
            dns_remove_record(dev)

def automatic_renew_certs(path: str, base: Path):
    """Automatically renew certificates for devices that are set to renew."""
    devices = load_devices(path)
    for device in devices:
        if device.automatic_renew and device.days_to_expiry():
            generatecert(device, base)
            if not device.redfish:
                asyncio.run(upload_cert_to_device(device, base))
            sleep(120)
            refresh_cert_info(device)
    save_devices(path, devices)

def refresh_cert_info_daily(path: str):
    """Refresh certificate information for all devices."""
    devices = load_devices(path)
    for device in devices:
        refresh_cert_info(device)
    save_devices(path, devices)



