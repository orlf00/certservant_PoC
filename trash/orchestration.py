import asyncio

from helpers import check_duplicity, check_expiry_sn, create_folder, delete_folder, generate, merge_files, move_files, upload_cert, write_json


def first_time(domena, alias_domena, soubor, prompt, login, password, env):
    create_folder(domena)
    code, msg = generate(domena, alias_domena, env)
    if code == 0:
        move_files(domena)
        merge_files(domena)
        asyncio.run(upload_cert(soubor, prompt, login, password,domena))
        return True

    delete_folder(domena)
    return False

def renew_cert(domena, alias_domena, soubor, prompt, login, password, env):
    generate(domena, alias_domena, env)
    move_files(domena)
    merge_files(domena)
    asyncio.run(upload_cert(soubor, prompt, login, password,domena))

def add_device_to_json(domena, alias_domena, prompt, login, password, nsup_key, nsup_server, nsup_zone, devices_file):
    exp, serial = check_expiry_sn(domena)
    nove_zarizeni = {
        "domena": domena,
        "alias_domena": alias_domena,
        "login": login,
        "password": password,
        "prompt": prompt,
        "nsupdate_key": nsup_key,
        "nsupdate_server": nsup_server,
        "nsupdate_zone": nsup_zone,
        "notafter": exp,
        "serial_num": serial,
        "automatic_renew": False,
    }
    if check_duplicity(domena, devices_file):
        return "Zařízení s touto doménou již existuje v seznamu."
    write_json(nove_zarizeni, devices_file)
    return None


app.route("/add-device", methods=["GET", "POST"])


def add_device():
    form = NameForm()
    if form.validate_on_submit():
        # Definování proměnných
        domena = form.url.data
        alias_domena = form.alias.data
        # soubor=f"/Users/filiporlicky/Desktop/BP/certy/{domena}/ssl.pem"
        prompt = form.prompt.data
        login = form.login.data
        password = form.password.data
        nsup_key = form.nsupdate_key.data
        nsup_server = form.nsupdate_server.data
        nsup_zone = form.nsupdate_zone.data

        add_device_to_json(domena, alias_domena, prompt, login, password, nsup_key, nsup_server, nsup_zone, devices_file)
        return redirect(url_for("index"))
        """ 
            TODO - sem dopsat ještě další params, mby ten login a password - ty jsou pro AI
            (promyslet neni to safe ale zas PoC) ale soubor, prompt - ty jsou pro AI
             (?a vlastně i ty envy nebo prostě ten odkaz na key server zone určitě?)
             + když bude funkce na cheknutí data do konce certu tak ten NotAfter

             - pak ta fce na kontrolu certů kontroluje podle názvu domény,
             když někde bude notafter pod 7 dní tak spustí
             1. generuj(zarizeni['domena'],zarizeni['alias_domena'])
                ^^^ ahoj, vygeneruj mi certifikát pro doménu kterou už znáš a alias taky
             2. presun(zarizeni['domena'])
                ^^^ teď mi ten certifikát přesuň do složky pro tu doménu
             3. spoj(zarizeni['domena'])
                ^^^ spoj mi dva soubory v té složce domény do jednoho
             4. asyncio.run(nahraj_cert(zarizeni['soubor'],zarizeni['prompt'],
                ^^^                     zarizeni['login'],zarizeni['heslo'])
                ^^^ teď pověř AI ať vezme ten soubor a použije stejný prompt, jako minule,
                    a přihlašovací údaje z minula, aby ho dostala do cíle

             5. uživatel tady už nic nepotvrzuje je to PoC tak nevim zda dam možnost delete
             6. envy vlastně nepotřebuju acme.sh je má uložené
             """

        """
             TODO - přidat určitě redirect na stránku kde se to uživatele zeptá,
                    zda vystavení proběhlo uspěšně a až pak založí JSON záznam,
                    popřípadě vymaže i složku.
            """

        """
            a = first_time(domena, alias_domena, soubor, prompt, login, password,env)
            if a:
                flash("Certifikát byl úspěšně vygenerován, zkontrolujte,"
                      " zda byl i úspěšně nahrán na zařízení", "success")
                exp = check_expiry(domena)
                nove_zarizeni["notafter"] = exp
                session["nove_zarizeni"] = nove_zarizeni
                session["domena"] = domena
                return redirect(url_for("potvrzeni"))
            flash("Při generování certifikátu nastala chyba, zkontrolujte"
                  " zadané údaje a zkuste to znovu.", "danger")
            return redirect(url_for("index"))
     """
    return render_template("new-device.html", form=form)


@app.route("/potvrzeni", methods=["GET", "POST"])
def potvrzeni():
    form = ConfirmForm()
    if form.validate_on_submit():
        nove_zarizeni = session.pop("nove_zarizeni", None)
        domena = session.pop("domena", None)
        if form.confirm.data:
            flash("Zařízení bylo přidáno do seznamu a bude pravidelně aktualizováno.", "success")
            write_json(nove_zarizeni, devices_file)
            return redirect(url_for("index"))
        # porovnat zda se certifikaty rovnaji pomoci serial nums
        # tlacitko pouze sledovat - nemusi to automaticky obnovovat
        # stazeni certu rucne z jsonu
        if form.deny.data:
            delete_folder(domena)
            flash("Zařízení bylo odstraněno z automatické obnovy.", "info")
            return redirect(url_for("index"))
    return render_template("confirm.html", form=form)


if __name__ == "__main__":
    app.run()

""" 

    Ahoj CertServant-e, uživatel po tobě chce abys mu vygeneroval certifikát,
    pro DOMÉNU. Vytvořil už dns záznam odkazující při _acme-challenge.DOMÉNA na _acme-challenge.ALIAS,
    ty nejdřív založ složku ve tvém adresáři pro certifikáty, která se bude jmenovat stejně jako DOMÉNA,
    pak pošli systému jeho proměnné pro NSUPDATE_KEY, NSUPDATE_SERVER a NSUPDATE_ZONE, potom popros
    terminál, ať spustí acme.sh v dns alias módua nacpe tam ty uživatelovy parametry pro DOMÉNU a ALIAS. 

    (sem možná ještě dát: JEDINĚ AŽ TI TERMINÁL POTVRDÍ, ŽE TO UDĚLAL ÚSPĚŠNĚ TAK POKRAČUJ DÁL)

    Pak ještě popros terminál, ať ti ten certifikát a privkey přesune do složky kterou jsi vytvořil
    ve svém adresáři.

    ### sem přidat ještě cheknutí do kdy je cert PLATNY_DO ###

    Ještě nemáš vyhráno, v tom tvém adresáři vezmi certifikát a privátní klíč a spoj je do jednoho
    SOUBORU. 

    Teď popros ai, ať se ti za pomoci PROMPTU přihlásí do zařízení pomocí přihlašovacích údajů
    #USER# a #PASSWORD# a nahraje tam ten SOUBOR.

    ###
    Jsi skoro u konce, poté co tohle doběhne, přesměřuj uživatele na stránku, kde potvrdí, že certifikát
    se úspěšně nahrál. Pokud klikne na volbu ano, přidej ho jako NOVE_ZARIZENI do tvého JSON souboru.
    Pokud klikne na ne, smaž složku, kterou jsi vytvořil pro jeho DOMÉNU.

    Teď už jen průběžně kontroluj, zda některému z certifikátů 
    ###

"""
