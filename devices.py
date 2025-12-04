from dataclasses import asdict, dataclass
from datetime import datetime


@dataclass
class Device:
    domain: str
    redfish: bool = False
    login: str | None = None
    password: str | None = None
    prompt: str | None = None
    # DNS parametry
    nsupdate_key: str | None = None
    nsupdate_server: str | None = None
    nsupdate_zone: str | None = None
    nsupdate_name: str | None = None
    nsupdate_subdomain: str | None = None
    # nepovinné
    renew_server: str | None = None
    eab_key: str | None = None
    eab_kid: str | None = None
    upload_key: bool = False
    upload_cert: bool = False
    upload_certkey: bool = False
    upload_fullchain: bool = False
    upload_intermediate: bool = False
    upload_interssl: bool = False
    keytype: str | None = None
    # doplní se potom, po úspěšném vytvoření certifikátu
    successful:bool = False
    automatic_renew: bool = False
    # doplní aplikace
    notafter: str | None = None
    serial_num: int | None = None
    local_sn: int | None = None
    last_renew: str | None = None
    id: int | None = None
    dload : bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Device":
        return cls(**d)

    def days_to_expiry(self, days: int=7) -> bool :
        expiry= datetime.fromisoformat(self.notafter)
        now= datetime.now()
        return (expiry-now).days <= days

