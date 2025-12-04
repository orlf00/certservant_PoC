
"""-----------------------------------------------AI Testing--------------------------------------------
import os

from browser_use import Agent, ChatGoogle, Browser
from dotenv import load_dotenv
import asyncio

load_dotenv()

FILE_TO_UPLOAD = '/Users/filiporlicky/PycharmProjects/FlaskProjectPTZ/testfile.jpg'
browser = Browser(
    headless=True
)

async def nahraj_cert():
    llm = ChatGoogle(model="gemini-flash-latest")
    task = "open uschovna.cz click on odeslat upload a file sender: login recipient: password and click on send"
    agent = Agent(task=task, llm=llm, file_system_path=os.path.dirname(FILE_TO_UPLOAD),available_file_paths=[FILE_TO_UPLOAD], browser=browser)
    await agent.run()

if __name__ == "__main__":
    asyncio.run(nahraj_cert())
"""# ------------------------------------------------Expirace--------------------------------------------


"""

def chekni_expiry():
    with open('devices.json') as f:
        data = json.load(f)
        print(data)
    for notafter in data['zarizeni']:
        expi = notafter['notafter']
        device = notafter['domena']
        datum = date.fromisoformat(expi)
        zamesic = date.today() + timedelta(days=30)
        if datum > zamesic:
            print(f"Platný do {datum} a je to u zařízení s doménou {device}")


if __name__ == "__main__":
    chekni_expiry()
    
"""
# -------------------------------------------------Test TLS browser-use---------------------------------------------

"""
import asyncio
import os

from browser_use import Agent, Browser, ChatOpenAI
from dotenv import load_dotenv

load_dotenv()

domena = "uschovna.cz"
FILE_TO_UPLOAD = "/Users/filiporlicky/PycharmProjects/FlaskProjectPTZ/testfile.jpg"
browser = Browser()

async def nahraj_cert():
    llm = ChatOpenAI(base_url="https://chat.ai.e-infra.cz/api", model="llama-4-scout-17b-16e-instruct", api_key="sk-5ca46f8fab954e3abebaa04591912524")
    task = ("go to ptz1.kme.vse.cz, login there with username: admin and password: 4w97gKthFRg46g5, click on camera config,"
            "then check again the elements, it will drop down and there you click on system settings."
            " terminate it there")
    agent = Agent(task=task, llm=llm, file_system_path=os.path.dirname(FILE_TO_UPLOAD),available_file_paths=[FILE_TO_UPLOAD], browser=browser)
    await agent.run()

if __name__ == "__main__":
    asyncio.run(nahraj_cert())
"""

"""
sk-5ca46f8fab954e3abebaa04591912524 = api klic k chat.ai.e-infra.cz
"""
#curl -H "Authorization: Bearer sk-5ca46f8fab954e3abebaa04591912524" https://chat.ai.e-infra.cz/api/models | jq .data[].id
"gpt-oss-120b"
"deepseek-r1"
"qwen3-coder"
"qwen2.5-coder:32b-instruct-q8_0"
"medgemma:27b-it"
"mistral-small3.2:24b-instruct-2506-q8_0"
"phi4:14b-q8_0"
"aya-expanse:32b"
"llama-4-scout-17b-16e-instruct"
"eocs-knowledge-base"
"metacentrum-docs-problemsolver"
"command-a:latest"
"mistral-small3.1:24b-instruct-2503-q8_0"
"llama3.3:latest"
"gemma3:27b-it"
"qwen2.5-coder:32b"
"rsqkit-research-software-quality"

# -------------------------------------------------Test knihovna ssl---------------------------------------------
"""
import ssl

from cryptography import x509


def check_expiry_sn(domena):
    a = ssl.get_server_certificate((domena, 443))
    b= x509.load_pem_x509_certificate(a.encode())
    expiry = b.not_valid_after_utc.date().isoformat()
    sn = b.serial_number
    return expiry, sn
if __name__ == "__main__":
    x, y= check_expiry_sn("ptz1.kme.vse.cz")
    print(x)
"""
# -------------------------------------------------Test helper---------------------------------------------
"""
from devices import Device
from helpers import add_device, load_devices

CERT_BASE = "/Users/filiporlicky/Desktop/BP/certy/"
JSON_KEY = "device"
DEVICES_FILE = "devices.json"


dev = Device(
    domain="necolepesadsiho.example.com",
    alias_domain="*.example.com",
    login="admin",
    password="heslo123",
    prompt="ahoj, nahraj cert na to zařízení",
    nsupdate_key="nějaký_tsig_key",
    nsupdate_server="ns1.example.com",
    nsupdate_zone="example.com",
)

# 2) přidám to do JSON
msg = add_device("devices.json", dev)

if msg is None:
    print("Device added!")
else:
    print("Cant be added", msg)

for d in load_devices("devices.json"):
    print(d)


dev = Device(
    domain="necojinak.example.com",
    alias_domain="*.example.com",
    login="sda",
    password="sadasd",
    prompt="ahoj, nahdasdraj cert na to zařízení",
    nsupdate_key="nějaký_tsig_key",
    nsupdate_server="ns1.example.com",
    nsupdate_zone="example.com",

    upload_certkey=True,
    upload_fullchain=False,
    upload_cert=False,
    upload_key=False,
    upload_imdca=False,
)


msg = add_device("devices.json", dev)

if msg is None:
    print("Device added")
else:
    print("Device cannot be added:", msg)

for d in load_devices("devices.json"):
    print(d)
"""
# -------------------------------------------------Test reading---------------------------------------------
"""
CERT_BASE = "/Users/filiporlicky/Desktop/BP/certy/ptz1.kme.vse.cz/"
key= "key.key"
cert= "cert.cer"
a = open(Path(CERT_BASE) / key).read()
b = open(Path(CERT_BASE) / cert).read()
c = a + b
d=open(Path(CERT_BASE) / "ssl.pem", "w").write(c)
print(d)
"""
# -------------------------------------------------folder.exists---------------------------------------------
"""
from pathlib import Path

base= "/Users/filiporlicky/Desktop/BP/certy"
domain = "ptz1.kme.cz"
def exists_folder():
    cesta= Path(base) / domain
    if cesta.exists():
        print("existuje")
    else:
        print("neexistuje")
if __name__ == "__main__":
    exists_folder()


-----BEGIN CERTIFICATE-----
MIIE9TCCBHqgAwIBAgIQFihIEtG9CURCDTB450DppzAKBggqhkjOPQQDAzBgMQswCQYDVQQGEwJH
UjE3MDUGA1UECgwuSGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJlc2VhcmNoIEluc3RpdHV0aW9ucyBD
QTEYMBYGA1UEAwwPR0VBTlQgVExTIEVDQyAxMB4XDTI1MTAyNTEwNTcwN1oXDTI2MTAyNTEwNTcw
N1owgYUxCzAJBgNVBAYTAkNaMR0wGwYDVQQIDBRIbGF2bsOtIG3Em3N0byBQcmFoYTEQMA4GA1UE
BwwHUHJhaGEgMzErMCkGA1UECgwiVnlzb2vDoSDFoWtvbGEgZWtvbm9taWNrw6EgdiBQcmF6ZTEY
MBYGA1UEAwwPcHR6MS5rbWUudnNlLmN6MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENtS6PERW
3UYqyTSGmX+Wf4LgDRe1AmPTrIxOPjmK3WEIRm5WrAskapAXdmWfOuhH7WsPYPL363/dgHcK2229
KaOCAu4wggLqMB8GA1UdIwQYMBaAFOmZBo0XH6v7lhpayFteXV7s2pyPMG8GCCsGAQUFBwEBBGMw
YTA4BggrBgEFBQcwAoYsaHR0cDovL2NydC5oYXJpY2EuZ3IvSEFSSUNBLUdFQU5ULVRMUy1FMS5j
ZXIwJQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLXRscy5oYXJpY2EuZ3IwGgYDVR0RBBMwEYIPcHR6
MS5rbWUudnNlLmN6MC0GA1UdIAQmMCQwCAYGZ4EMAQICMAgGBgQAj3oBBzAOBgwrBgEEAYHPEQEB
AQIwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6
Ly9jcmwuaGFyaWNhLmdyL0hBUklDQS1HRUFOVC1UTFMtRTEuY3JsMB0GA1UdDgQWBBQKnBY3/nky
kUYHhhTr5ZK/zWBfFTAOBgNVHQ8BAf8EBAMCB4AwggF8BgorBgEEAdZ5AgQCBIIBbASCAWgBZgB2
ANdtfRDRp/V3wsfpX9cAv/mCyTNaZeHQswFzF8DIxWl3AAABmhsNBDMAAAQDAEcwRQIgY8wKHUtb
7reHH+KuL7XNJ5SJ86FO9YsnRIU6pMz9r2cCIQDEQ/syqARzOcrhE4fkB/PUE9NMKBcbm0UovnV0
7AjgugB0AMs49xWJfIShRF9bwd37yW7ymlnNRwppBYWwyxTDFFjnAAABmhsNBXIAAAQDAEUwQwIf
BnzdbI7r/sVZv791a9MmUqJ0REiPfy8B4SWwRKNdRQIgRNxRgKlbMi8JkJVZjDGcQBDmBH9T/T9L
hEUSfeSyxesAdgDYCVU7lE96/8gWGW+UT4WrsPj8XodVJg8V0S5yu0VLFAAAAZobDQQBAAAEAwBH
MEUCIAsa1vPo6/kwNczChssI5TjjJJ7MxOQde8WFvFOSm5OuAiEAl371zv5nevgZ13XFUe5K9csr
be5YUwMIU+rzYa7XTOMwCgYIKoZIzj0EAwMDaQAwZgIxAJ5EuEcBG/DgixPlaQrs6/+JOtDk3iY7
EwvW1ZyKDoauBvc0faZetAifNhzH3LgorQIxANDofuk+zsTJg3pfn9360GWdKTqGAzn4RuYuL7/7
wlnEBC8eds+EgEqt0SMoSrsYZg==
-----END CERTIFICATE-----
"""
