Před nasazením je důležité vytvořit v adresáři složku "crt" a soubor ".env" obsahující tyto proměnné:

ANONYMIZED_TELEMETRY=false (VOLITELNÉ, ZAKÁŽE ODESÍLÁNÍ BROWSER-USE DAT)
BROWSER_USE_API_KEY = (API KLÍČ K BROWSER-USE LLM)
SECRET_KEY = (VYGENEROVANÝ TAJNÝ KLÍČ POUŽITÝ VE FORMULÁŘI PROTI CSRF ÚTOKŮM)
JSON_KEY="device" (NÁZEV ZAŘÍZENÍ V JSONU)
USER_AGENT= "CertServant PoC" (NÁZEV ACME KLIENTA)
