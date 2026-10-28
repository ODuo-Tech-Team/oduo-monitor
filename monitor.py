#!/usr/bin/env python3
"""
Monitor do site ODuo — roda no GitHub Actions (always-on), independente de máquina pessoal.

Verifica, para www.oduo.com.br / oduo.com.br / /maquinas:
  1. HTTP GET completo        -> pega queda de TLS antes de qualquer HTTP
  2. Prazo do certificado TLS -> alerta com antecedência (21/7/3/1/0 dias) ou VENCIDO
  3. Quem está servindo       -> detecta WordPress no domínio (sinal de DNS revertido)

Avisa no Google Chat SÓ na virada (caiu/voltou, cruzou faixa de cert) — sem spam.
Estado persistido entre execuções via cache do Actions (state.json).

Variáveis de ambiente:
  GCHAT_WEBHOOK  URL do webhook do Google Chat (secret). Sem ela, só loga.
  FORCE_TEST=1   envia uma mensagem de teste no Chat (disparo manual).
  STATE_FILE     caminho do arquivo de estado (default: state.json).
"""
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone

STATE_FILE = os.environ.get("STATE_FILE", "state.json")
WEBHOOK = os.environ.get("GCHAT_WEBHOOK", "").strip()
FORCE_TEST = os.environ.get("FORCE_TEST", "") == "1"

HTTP_TARGETS = [
    ("home", "https://www.oduo.com.br/"),
    ("root", "https://oduo.com.br/"),
    ("maquinas", "https://www.oduo.com.br/maquinas"),
]
CERT_HOSTS = ["www.oduo.com.br", "oduo.com.br"]
CERT_THRESHOLDS = [0, 1, 3, 7, 21]  # faixas de alerta (dias restantes)
TIMEOUT = 20
UA = "oduo-monitor/1.0 (+github-actions)"


def http_check(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(20000).decode("utf-8", "ignore")
            return {
                "ok": 200 <= r.status < 400,
                "status": r.status,
                "server": r.headers.get("Server", ""),
                "powered": r.headers.get("X-Powered-By", ""),
                "body": body,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {
            "ok": False,
            "status": e.code,
            "server": (e.headers.get("Server", "") if e.headers else ""),
            "powered": "",
            "body": "",
            "error": f"HTTP {e.code}",
        }
    except Exception as e:
        return {"ok": False, "status": None, "server": "", "powered": "", "body": "", "error": f"{type(e).__name__}: {e}"}


def looks_wordpress(res):
    b = (res.get("body") or "").lower()
    p = (res.get("powered") or "").lower()
    s = (res.get("server") or "").lower()
    if "wp-content" in b or "wp-json" in b or "wordpress" in b:
        return True
    if "php" in p and "vercel" not in s:
        return True
    return False


def serving_identity(res):
    s = (res.get("server") or "").lower()
    if looks_wordpress(res):
        return "wordpress"
    if "vercel" in s:
        return "vercel"
    return "unknown" if res.get("ok") else "down"


def cert_days(host):
    """Retorna (days:int, exp:datetime, None) | ('EXPIRED', None, msg) | (None, None, erro)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        na = cert["notAfter"].replace(" GMT", "")
        exp = datetime.strptime(na, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        return days, exp, None
    except ssl.SSLCertVerificationError as e:
        if "expired" in str(e).lower():
            return "EXPIRED", None, str(e)
        return None, None, str(e)
    except Exception as e:
        return None, None, f"{type(e).__name__}: {e}"


def cert_band(days):
    """Faixa mais apertada que o prazo cruzou; None se saudável (>21 dias)."""
    for t in CERT_THRESHOLDS:  # 0,1,3,7,21
        if days <= t:
            return t
    return None


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def save_state(st):
    st["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(STATE_FILE, "w") as f:
        json.dump(st, f, indent=2)


def notify(text):
    if not WEBHOOK:
        print("[WARN] GCHAT_WEBHOOK vazio — não enviei:", text.replace("\n", " | "))
        return
    data = json.dumps({"text": text}).encode()
    req = urllib.request.Request(WEBHOOK, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            print("[chat]", r.status, "|", text.replace("\n", " | "))
    except Exception as e:
        print("[ERRO chat]", e)


def main():
    st = load_state()
    prev_http = st.get("http", {})
    prev_serv = st.get("serving", {})
    prev_cert = st.get("cert", {})
    new_http, new_serv, new_cert = {}, {}, {}
    alerts = []

    # 1) HTTP GET + guarda resultado para a checagem de "quem serve"
    results = {}
    for name, url in HTTP_TARGETS:
        res = http_check(url)
        results[name] = (url, res)
        state = "up" if res["ok"] else "down"
        new_http[name] = state
        prev = prev_http.get(name)
        detail = res["error"] or f"HTTP {res['status']}"
        if prev is None:
            if state == "down":
                alerts.append(f"🔴 *CAIU* — {name} ({url})\n{detail}")
        elif prev != state:
            if state == "down":
                alerts.append(f"🔴 *CAIU* — {name} ({url})\n{detail}")
            else:
                alerts.append(f"✅ *VOLTOU* — {name} ({url}) — HTTP {res['status']}")

    # 3) Quem está servindo (detecta WordPress = DNS revertido)
    serv_map = {"www.oduo.com.br": "home", "oduo.com.br": "root"}
    for host, tname in serv_map.items():
        _, res = results.get(tname, (None, {"ok": False}))
        ident = serving_identity(res)
        new_serv[host] = ident
        prev = prev_serv.get(host)
        if ident == "wordpress" and prev != "wordpress":
            alerts.append(f"⚠️ *DNS REVERTIDO?* — {host} está sendo servido por *WordPress* (esperado: Vercel). Conferir DNS já.")
        elif prev == "wordpress" and ident == "vercel":
            alerts.append(f"✅ *NORMALIZADO* — {host} voltou a ser servido pela Vercel.")

    # 2) Certificado TLS
    for host in CERT_HOSTS:
        days, exp, err = cert_days(host)
        prev = prev_cert.get(host)
        prev_band = None if prev in (None, "ok") else prev

        if days == "EXPIRED":
            new_cert[host] = 0
            if prev_band is None or prev_band > 0:
                alerts.append(f"🟠 *CERTIFICADO VENCIDO* — {host}. Renovar IMEDIATAMENTE.")
            continue
        if err or days is None:
            print(f"[cert] {host}: erro ao ler ({err}) — queda de TLS cai no alerta de HTTP")
            new_cert[host] = prev if prev is not None else "ok"
            continue

        band = cert_band(days)
        new_cert[host] = band if band is not None else "ok"
        if band is not None:
            if prev_band is None or band < prev_band:  # entrou/apertou faixa de alerta
                lbl = "VENCIDO" if days <= 0 else f"vence em {days} dia(s)"
                alerts.append(f"🟠 *CERTIFICADO* — {host} {lbl} (expira {exp:%d/%m/%Y}). Renovar já.")
        elif prev_band is not None:  # saiu da zona de alerta -> renovado
            alerts.append(f"✅ *CERT OK* — {host} renovado (expira {exp:%d/%m/%Y}, {days} dias).")

    save_state({"http": new_http, "serving": new_serv, "cert": new_cert})

    if FORCE_TEST:
        notify("🧪 Teste do monitor ODuo — webhook do Google Chat está funcionando. (disparo manual)")

    for a in alerts:
        notify(a)

    # resumo no log do Actions
    print("HTTP   :", new_http)
    print("SERVING:", new_serv)
    print("CERT   :", new_cert)
    print(f"{len(alerts)} alerta(s) enviado(s) ao Chat.")


if __name__ == "__main__":
    main()
