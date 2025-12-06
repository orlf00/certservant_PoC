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

