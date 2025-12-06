"""CertServant - Automated TLS Certificate Management for Devices
Copyright (C) 2025  Filip Orlický

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import json
import os
import shutil
import ssl
import time
from pathlib import Path
from time import sleep

import dns.query
import dns.tsigkeyring
import dns.update
import redfish
from acme import challenges, crypto_util
from browser_use import Agent, Browser, ChatBrowserUse
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from dotenv import load_dotenv

from devices import Device

load_dotenv()
USER_AGENT= os.getenv("USER_AGENT")
JSON_KEY= os.getenv("JSON_KEY")

def new_csr_comp(domain_name, keytype, pkey_pem=None):
    """Create certificate signing request."""
    if pkey_pem is None:
        # Create private key.
        match keytype:
            case "rsa2048":
                pkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            case "rsa3072":
                pkey = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            case "rsa4096":
                pkey = rsa.generate_private_key(public_exponent=65537, key_size=4096)
            case "ec256":
                pkey = ec.generate_private_key(ec.SECP256R1())
            case "ec384":
                pkey = ec.generate_private_key(ec.SECP384R1())
            case "ec521":
                pkey = ec.generate_private_key(ec.SECP521R1())
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
    """Adds DNS TXT record for ACME DNS-01 challenge."""
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
    """Removes DNS TXT record for ACME DNS-01 challenge."""
    keyring = dns.tsigkeyring.from_text(
        {
            f"{dev.nsupdate_name}": f"{dev.nsupdate_key}",
        },
    )
    update = dns.update.UpdateMessage(f"{dev.nsupdate_zone}", keyring=keyring)
    update.delete(f"_acme-challenge.{dev.nsupdate_subdomain}", "TXT")
    response = dns.query.tcp(update, f"{dev.nsupdate_server}")
    print("DNS record removed.")

def create_files(leaf, pkey, fullchain, intermediate, base, dev: Device):
    """Creates certificate files in the specified directory."""
    base = Path(base) / dev.domain

    base.mkdir(parents=True, exist_ok=True)
    if dev.redfish:
        (base / "cert.pem").write_text(leaf, encoding="utf-8")
        (base / "fullchain.pem").write_text(fullchain, encoding="utf-8")
        (base / "intermediate.pem").write_text(intermediate, encoding="utf-8")
    else:
        (base / "cert.pem").write_text(leaf, encoding="utf-8")
        (base / "privkey.key").write_text(pkey, encoding="utf-8")
        (base / "fullchain.pem").write_text(fullchain, encoding="utf-8")
        (base / "intermediate.pem").write_text(intermediate, encoding="utf-8")
        (base / "ssl.pem").write_text(pkey + leaf, encoding="utf-8")
        (base / "sslinter.pem").write_text(pkey + intermediate, encoding="utf-8")


def cert_paths(dev: Device, base: Path) -> dict[str, str]: #helper
    """Gives paths to certificate files for a device."""
    d = Path(base) / dev.domain
    return {
        "dir": str(d),
        "key": str(d / "privkey.key"),
        "cert": str(d / "cert.pem"),
        "certkey": str(d / "ssl.pem"),
        "fullchain": str(d / "fullchain.pem"),
        "intermediate": str(d / "intermediate.pem"),
        "interssl": str(d / "sslinter.pem"),
    }

def build_upload_files(dev: Device, base: Path) -> list[str]: #helper
    """Builds a list of files to upload based on device settings."""
    p = cert_paths(dev, base)
    files: list[str] = []
    if dev.upload_key:
        files.append(p["key"])
    if dev.upload_cert:
        files.append(p["cert"])
    if dev.upload_certkey:
        files.append(p["certkey"])
    if dev.upload_fullchain:
        files.append(p["fullchain"])
    if dev.upload_intermediate:
        files.append(p["intermediate"])
    if dev.upload_interssl:
        files.append(p["interssl"])
    return files

def delete_folder(dev: Device, base: Path): #helper
    """Deletes the certificate folder for a device."""
    cesta = Path(base) / dev.domain
    if cesta.exists():
        shutil.rmtree(cesta, ignore_errors=True)
        print(f"Složka {cesta} byla smazána.")
        return "Složka pro certifikáty byla smazána"
    print("Složka neexistuje, nic se nemaže.")
    return f"Složka {cesta} neexistuje."

async def upload_cert_to_device(dev: Device, base: Path) -> None:
    """Uploads certificate to the device using browser automation."""
    paths = cert_paths(dev, base)
    files = build_upload_files(dev, base)

    browser = Browser(
        headless=True,
        keep_alive=False,
        disable_security=True,
        allowed_domains=[f"*.{dev.domain}"],
        paint_order_filtering=True,
        highlight_elements=True,
        wait_between_actions=2.0,
    )

    agent = Agent(
        task=dev.prompt,
        llm=ChatBrowserUse(),
        file_system_path=paths["dir"],
        available_file_paths=files,
        browser=browser,
        sensitive_data={"login": dev.login, "password": dev.password},
        use_vision=False,
    )
    await agent.run(max_steps=20)
    await agent.close()

def refresh_cert_info(dev: Device) -> bool:
    """Refreshes certificate information (notafter date and serial number) for a device."""
    pem = ssl.get_server_certificate((dev.domain, 443))
    cert = x509.load_pem_x509_certificate(pem.encode())
    new_notafter = cert.not_valid_after.date().isoformat()
    new_serial = cert.serial_number
    changed = False
    if dev.notafter != new_notafter:
        dev.notafter = new_notafter
        changed = True
    if dev.serial_num != new_serial:
        dev.serial_num = new_serial
        changed = True
    return changed

def domain_exists(path: str, domena: str) -> bool:
    """Checks if a device with the given domain exists in the JSON file."""
    return any(d.domain == domena for d in load_devices(path))

def load_devices(path: str) -> list[Device]:
    """Loads devices from a JSON file."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    items = data.get(JSON_KEY, [])
    return [Device.from_dict(it) for it in items]

def save_devices(path: str, devices: list[Device]) -> None:
    """Saves devices to a JSON file."""
    data = { JSON_KEY: [d.to_dict() for d in devices] }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def delete_device(path: str, item_id: int) -> bool:
    """Deletes a device by its ID from the JSON file."""
    devices = load_devices(path)
    new_list = [d for d in devices if d.id != item_id]
    if len(new_list) == len(devices):
        return False
    save_devices(path, new_list)
    return True

def update_device(path: str, item_id: int, new_device: Device) -> bool:
    """Updates a device by its ID in the JSON file."""
    devices = load_devices(path)
    idx = next((i for i, d in enumerate(devices) if d.id == item_id), None)
    if idx is None:
        return False

    new_device.id = item_id
    refresh_cert_info(new_device)
    devices[idx] = new_device
    save_devices(path, devices)
    return True

def ilofish_csr(dev: Device):
    """Generates a CSR on the device using Redfish API."""
    telo = {
        "City": "Praha",
        "CommonName": dev.domain,
        "Country": "CZ",
        "OrgName": "VSE",
        "OrgUnit": "KME",
        "State": "Bohemia",
    }
    REST_OBJ = redfish.RedfishClient(
        base_url=f"https://{dev.domain}", username=dev.login, password=dev.password,
    )
    REST_OBJ.login(auth="session")

    response = REST_OBJ.post(
        "/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpHttpsCert.GenerateCSR/",
        body=telo,
    )

    deadline = time.time() + 600

    clean_csr = None
    while time.time() < deadline:
        csr_response = REST_OBJ.get("/redfish/v1/Managers/1/SecurityService/HttpsCert/")
        if "CertificateSigningRequest" in csr_response.dict:
            clean_csr = csr_response.dict["CertificateSigningRequest"]
            break
        time.sleep(3)  # čekej 3 sekundy a zkus znovu

    if clean_csr:
        return clean_csr
    print("CSR se neobjevil do 3 minut.")
    REST_OBJ.logout()
    return None

def ilofish_deploy(cert_body, dev: Device):
    """Deploys a certificate to the device using Redfish API."""
    REST_OBJ = redfish.RedfishClient(
        base_url=f"https://{dev.domain}", username=dev.login, password=dev.password,
    )
    REST_OBJ.login(auth="session")
    dictionary={
        "Certificate": cert_body,
    }
    response = REST_OBJ.post(
        "/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/HpHttpsCert.ImportCertificate/",
        body=dictionary,
    )
    REST_OBJ.logout()

def has_directory(dev: Device, base: Path) -> bool:
    """Checks if the certificate directory for a device exists and is not empty."""
    cesta = Path(base) / dev.domain
    return cesta.is_dir() and any(cesta.iterdir())

def check_cert_file_serial(certfile: str) -> int:
    """Checks the serial number of a certificate in file."""
    byte_cert= certfile.encode("utf-8")
    cert = x509.load_pem_x509_certificate(byte_cert)
    return cert.serial_number




