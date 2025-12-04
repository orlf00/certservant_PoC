import asyncio
import os
from datetime import datetime
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from flask_apscheduler import APScheduler

from devices import Device
from forms import ConfirmForm, DeleteForm, NameForm, RefreshForm
from helpers import delete_device, delete_folder, has_directory, load_devices, save_devices, update_device, upload_cert_to_device
from logic import add_device, automatic_renew_certs, generatecert, refresh_cert_info_daily

load_dotenv()

devices_file = "devices.json"
base_folder = Path(__file__).parent / "crt"
app = Flask(__name__)

scheduler = APScheduler()
scheduler.init_app(app)

@scheduler.task("interval", hours=24, id="autocheck", max_instances=1,
                coalesce=True, next_run_time=datetime.now())
def autocheck():
    refresh_cert_info_daily(devices_file)
    automatic_renew_certs(devices_file, base_folder)
    refresh_cert_info_daily(devices_file)
scheduler.start()

app.config["SECRET_KEY"]=os.getenv("SECRET_KEY")
@app.route("/", methods=["GET"])
def index():
    form=RefreshForm()
    devices = load_devices(devices_file)
    return render_template("index.html", devices=devices, form=form)

@app.route("/add-device", methods=["GET", "POST"])
def add_device_route():
    form = NameForm()
    if form.validate_on_submit():
        dev = Device(
            domain=form.url.data,
            redfish= form.redfish.data,
            login=form.login.data,
            password=form.password.data,
            prompt=form.prompt.data,
            nsupdate_key=form.nsupdate_key.data,
            nsupdate_server=form.nsupdate_server.data,
            nsupdate_zone=form.nsupdate_zone.data,
            nsupdate_name=form.nsupdate_name.data,
            nsupdate_subdomain=form.nsupdate_subdomain.data,
            renew_server=form.renew_server.data,
            eab_key=form.eab_key.data,
            eab_kid=form.eab_kid.data,
            upload_key=form.upload_key.data,
            upload_cert=form.upload_cert.data,
            upload_certkey=form.upload_certkey.data,
            upload_fullchain=form.upload_fullchain.data,
            upload_intermediate=form.upload_intermediate.data,
            upload_interssl=form.upload_interssl.data,
            keytype=form.keytype.data,

        )
        add_device(dev, devices_file)
        flash("Zařízení bylo úspěšně přidáno.", "success")
        return redirect(url_for("index"))
    return render_template("new-device.html", form=form,
                           form_action=url_for("add_device_route"),
                           submit_label="Přidat zařízení", mode="add", device=None)

@app.route("/edit-device/<int:device_id>", methods=["GET", "POST"])
def edit_device_route(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))

    if request.method == "GET":
        form = NameForm(data={
            "url": device.domain,
            "redfish": device.redfish,
            "login": device.login,
            "password": device.password,
            "prompt": device.prompt,
            ###
            "nsupdate_key": device.nsupdate_key,
            "nsupdate_server": device.nsupdate_server,
            "nsupdate_zone": device.nsupdate_zone,
            "nsupdate_name": device.nsupdate_name,
            "nsupdate_subdomain": device.nsupdate_subdomain,
            "keytype": device.keytype,
            ###
            "renew_server": device.renew_server,
            "eab_kid": device.eab_kid,
            "eab_key": device.eab_key,
            "upload_key": device.upload_key,
            "upload_cert": device.upload_cert,
            "upload_certkey": device.upload_certkey,
            "upload_fullchain": device.upload_fullchain,
            "upload_intermediate": device.upload_intermediate,
            "upload_interssl": device.upload_interssl,
            "automatic_renew": device.automatic_renew,
        })
        return render_template(
            "new-device.html", form=form,
            form_action=url_for("edit_device_route", device_id=device_id),
            submit_label="Uložit změny", mode="edit", device=device,
        )

    # POST
    form = NameForm()
    if form.validate_on_submit():
        new_dev = Device(
            domain=form.url.data,
            redfish=form.redfish.data,
            login=form.login.data,
            password=form.password.data or device.password,
            prompt=form.prompt.data,
            nsupdate_key=form.nsupdate_key.data,
            nsupdate_server=form.nsupdate_server.data,
            nsupdate_zone=form.nsupdate_zone.data,
            nsupdate_name=form.nsupdate_name.data,
            nsupdate_subdomain=form.nsupdate_subdomain.data,
            renew_server=form.renew_server.data,
            eab_key=form.eab_key.data,
            eab_kid=form.eab_kid.data,
            upload_key=form.upload_key.data,
            upload_cert=form.upload_cert.data,
            upload_certkey=form.upload_certkey.data,
            upload_fullchain=form.upload_fullchain.data,
            upload_intermediate=form.upload_intermediate.data,
            upload_interssl=form.upload_interssl.data,
            keytype=form.keytype.data,
            successful=device.successful,
            automatic_renew=form.automatic_renew.data,
            notafter=device.notafter,
            serial_num=device.serial_num,
            local_sn=device.local_sn,
            last_renew=device.last_renew,
            dload=device.dload,
        )

        update_device(devices_file, device_id, new_dev)
        flash("Zařízení bylo upraveno.", "success")
        return redirect(url_for("index"))

    return render_template("new-device.html", form=form,
                           form_action=url_for("edit_device_route", device_id=device_id),
                           submit_label="Uložit změny", mode="edit", device=device)

@app.route("/delete-device/<int:device_id>", methods=["GET", "POST"])
def delete_device_route(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))

    form= ConfirmForm()
    if form.validate_on_submit():
        if form.confirm.data:
            delete_device(devices_file, device_id)
            delete_folder(device,base_folder)
            flash("Zařízení bylo odstraněno.", "success")
            return redirect(url_for("index"))
        if form.deny.data:
            flash("Operace byla zrušena.", "info")
            return redirect(url_for("index"))
    return render_template("delete-confirmation.html", form=form, device_id=device_id)

@app.route("/renew-cert/<int:device_id>/generate", methods=["GET"])
def generate_cert_route(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))
    if not all([
        device.login,
        device.password,
        device.nsupdate_key,
        device.nsupdate_server,
        device.nsupdate_zone,
        device.nsupdate_name,
        device.nsupdate_subdomain,
        device.renew_server,
        device.keytype,
    ]):
        flash("Nelze spustit generování certifikátu - některé povinné údaje nejsou vyplněny.", "warning")
        return redirect(url_for("index"))

    generatecert(device, base_folder)
    save_devices(devices_file, devices)

    if device.redfish:
        return redirect(url_for("potvrzeni", device_id=device_id))
    return redirect(url_for("upload_cert_route", device_id=device_id))

@app.route("/renew-cert/<int:device_id>/upload", methods=["GET"] )
def upload_cert_route(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))
    asyncio.run(upload_cert_to_device(device, base_folder))
    flash("Certifikát nahrán.", "success")
    return redirect(url_for("potvrzeni", device_id=device_id))

@app.route("/renew-cert/<int:device_id>/potvrzeni", methods=["GET", "POST"])
def potvrzeni(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))

    form = ConfirmForm()
    if form.validate_on_submit():
        if form.confirm.data:
            if form.renew.data:
                device.automatic_renew=True
                device.successful=True
                device.dload=has_directory(device, base_folder)
                update_device(devices_file, device_id, device)
            else:
                device.automatic_renew=False
                device.successful=True
                device.dload=has_directory(device, base_folder)
                update_device(devices_file, device_id, device)
            return redirect(url_for("index"))
        if form.renew.data:
            device.automatic_renew=False
            update_device(devices_file, device_id, device)
            flash("Nelze nastavit automatickou obnovu, certifikát nebyl nahrán na zařízení.", "warning")
        return redirect(url_for("potvrzeniosmazani", device_id=device_id))
    return render_template("confirm.html", form=form, device=device)

@app.route("/renew-cert/<int:device_id>/potvrzeniosmazani", methods=["GET", "POST"])
def potvrzeniosmazani(device_id):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))

    form = DeleteForm()
    if form.validate_on_submit():
        if form.confirm.data:
            delete_folder(device, base_folder)
            device.dload=False
            update_device(devices_file, device_id, device)
            flash("Složka s certifikáty byla odstraněna.", "success")
            return redirect(url_for("index"))
        device.dload=has_directory(device, base_folder)
        update_device(devices_file, device_id, device)
        flash("Operace byla zrušena.", "info")
        return redirect(url_for("index"))
    return render_template("deleteconfirm.html", form=form, device=device)

@app.route("/download/<int:device_id>/<filetype>", methods=["GET"])
def dwncert(device_id, filetype):
    devices = load_devices(devices_file)
    device = next((d for d in devices if d.id == device_id), None)
    if not device:
        flash("Zařízení nenalezeno.", "danger")
        return redirect(url_for("index"))
    if not has_directory(device, base_folder):
        flash("Složka s certifikáty neexistuje.", "danger")
        return redirect(url_for("index"))
    files = {
        "cert": "cert.pem",
        "pkey": "privkey.key",
        "chain": "fullchain.pem",
        "keycert": "ssl.pem",
        "intermediate": "intermediate.pem",
        "interssl": "sslinter.pem",
    }
    cert_path = Path(base_folder) / device.domain / files[filetype]
    return send_file(cert_path, as_attachment=True)

@app.route("/refresh", methods=["POST"]) # TODO dodelat
def refresh():
    refresh_cert_info_daily(devices_file)
    flash("Informace o certifikátech byly obnoveny.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
