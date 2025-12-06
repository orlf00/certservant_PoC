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
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.fields.choices import SelectField
from wtforms.fields.simple import BooleanField
from wtforms.validators import DataRequired


class NameForm(FlaskForm):

    ## Data potřebná k ACME validaci
    url = StringField("URL  !! bez https !!", validators=[DataRequired()])
    redfish = BooleanField("Zařízení podporuje Redfish API")
    login = StringField("Login do zařízení:")
    password = PasswordField("Heslo do zařízení:")
    prompt = StringField("Prompt pro nahrání certu (anglicky):")
    ## DNS parametry pro nsupdate
    nsupdate_key = StringField("TSIG klíč:")
    nsupdate_server = StringField("Nsupdate server:")
    nsupdate_zone = StringField("Zóna nsupdate:")
    nsupdate_name = StringField("Název TSIG klíče:")
    nsupdate_subdomain = StringField("Nsupdate subdoména [např. pro *.(nsupdate_zone) zadejte *]:")
    ## ACME veci
    renew_server = StringField("ACME poskytovatel:", render_kw={"list":"providers"})
    eab_key = StringField("EAB Key:")
    eab_kid = StringField("EAB KID:")
    upload_key = BooleanField("Nahrát soukromý klíč")
    upload_cert = BooleanField("Nahrát certifikát")
    upload_certkey = BooleanField("Nahrát certifikát spojený s klíčem v 1 souboru")
    upload_fullchain = BooleanField("Nahrát fullchain certifikát")
    upload_intermediate = BooleanField("Nahrát certifikát+intermediate")
    upload_interssl = BooleanField("Nahrát certifikát+intermediate spojený s klíčem v 1 souboru")
    keytype = SelectField(  "Keytype", choices=[("rsa2048", "RSA 2048"),("rsa3072", "RSA 3072"),("rsa4096", "RSA 4096"),
            ("ec256", "EC 256"),("ec384", "EC 384"),("ec521", "EC 521")],default="rsa2048")
    automatic_renew = BooleanField("Automaticky obnovovat certifikát před vypršením platnosti")
    button = SubmitField("Submit")

class ConfirmForm(FlaskForm):
    confirm = SubmitField("Ano")
    deny = SubmitField("Ne")
    renew = BooleanField("Automaticky obnovovat certifikát před vypršením platnosti")

class DeleteForm(FlaskForm):
    confirm = SubmitField("Smazat složku")
    deny = SubmitField("Nemazat složku")

class RefreshForm(FlaskForm):
    pass

