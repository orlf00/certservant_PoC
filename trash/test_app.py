import os

from app import *

## proměnné
"""
domena = "test"
cesta = f"/Users/filiporlicky/Desktop/BP/testy/{domena}"
alias_domena = "alias_test"
zarizeni = "devices.json"
soubor = None
prompt = None
login = None
password = None

"""
domena="ptz1.kme.vse.cz"
cesta = f"/Users/filiporlicky/Desktop/BP/certy/{domena}"
alias_domena = "ptz1.kme._le.vse.cz"
zarizeni = "devices.json"


komplet(domena, alias_domena, soubor, prompt, login, password)

if __name__ == "__main__":
    komplet(domena, alias_domena, soubor, prompt, login, password)

go to ptz1.kme.vse.cz, login with username and password. On the left panel you will see "camera config" click on it, the dropdown menu will append, where you will see "system settings" button. click on it, now you can see the "select file from your computer" button. Upload there the file ssl.pem and click on apply.

# promyslet jestli to nedat v pythonu
#pridat moznost nespojovat privkey a cert
def merge_files(domena):
    # spojení privkey a certu TODO - nechat na bázi dobrovolnosti
    subprocess.run(["cat", f"/Users/filiporlicky/Desktop/BP/certy/{domena}/cert.cer",
                    f"/Users/filiporlicky/Desktop/BP/certy/{domena}/key.key"],
                   check=False, stdout=open(f"/Users/filiporlicky/Desktop/BP/certy/{domena}/ssl.pem", "w"))
    return "Soubory byly úspěšně spojeny do jednoho .pem souboru"

acme.sh --issue -d ptz1.kme.vse.cz --server https://acme-v02.harica.gr/acme/4dba53c2-54fa-4c4a-bddd-b3c54815ed71/directory --eab-kid E31fC8GZJB0wBWq4QMPc --eab-hmac-key ZfwRYTG8CN1jsbWs3FZVfRhDRTjbzHqIgR0aXRdrP8Y --dns dns_nsupdate --challenge-alias ptz1.kme._le.vse.cz
acme.sh --issue -d ptz1.kme.vse.cz --server https://acme-v02.harica.gr/acme/4dba53c2-54fa-4c4a-bddd-b3c54815ed71/directory --dns dns_nsupdate --challenge-alias ptz1.kme._le.vse.cz