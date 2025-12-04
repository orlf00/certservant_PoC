import dns.query
import dns.tsigkeyring
import dns.update


def dns_add_record():
    keyring = dns.tsigkeyring.from_text(
        {
            "_le.vse.cz_ddns_update": "wL7prYtCW4zd/0g9nY9i4A8+OE946odG5lr0GHdJB44=",
        },
    )
    update = dns.update.UpdateMessage("_le.vse.cz.", keyring=keyring)
    update.replace("ptz1.kme", 300, "TXT", "Testing_dnspython")
    response = dns.query.tcp(update, "146.102.42.42")

def dns_remove_record():
    keyring = dns.tsigkeyring.from_text(
        {
            "_le.vse.cz_ddns_update": "wL7prYtCW4zd/0g9nY9i4A8+OE946odG5lr0GHdJB44=",
        },
    )
    update = dns.update.UpdateMessage("_le.vse.cz.", keyring=keyring)
    update.delete("_acme-challenge.ptz1.kme", "TXT")

    response = dns.query.tcp(update, "146.102.42.42")
    print("DNS record removed.")

if __name__ == "__main__":
    dns_remove_record()
