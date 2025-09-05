# app.py
# TelePorte Admin + API (Flask + PocketBase)
# Roda no Render, protegido, com sessão e segurança

from flask import Flask, request, render_template, redirect, url_for, session, abort
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta
import requests
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "mudar_em_producao")
app.permanent_session_lifetime = timedelta(minutes=30)  # Sessão expira em 30 min

# === CONFIGURAÇÃO DO POCKETBASE ===
POCKETBASE_URL = os.environ.get("POCKETBASE_URL", "http://localhost:8090")
ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]  # Hash da senha (via Render)

# === CONTROLE DE TENTATIVAS (Rate Limit) ===
tentativas_login = {}  # {ip: [datetime, ...]}
MAX_TENTATIVAS = 5
JANELA_MINUTOS = 15

def sanitizar_senha(senha: str) -> str:
    """Remove caracteres potencialmente maliciosos da senha."""
    if not senha:
        return ""
    # Permite: letras, números, e símbolos comuns em senhas
    return re.sub(r'[^\w\s@!#$%&*+\-=?^_`{|}~]', '', senha)

def verificar_rate_limit(ip: str) -> bool:
    agora = datetime.now()
    if ip not in tentativas_login:
        tentativas_login[ip] = []
    # Remove tentativas antigas
    tentativas_login[ip] = [
        t for t in tentativas_login[ip] if agora - t < timedelta(minutes=JANELA_MINUTOS)
    ]
    return len(tentativas_login[ip]) < MAX_TENTATIVAS

def registrar_tentativa(ip: str):
    tentativas_login.setdefault(ip, []).append(datetime.now())

# === PROTEÇÃO DE ROTAS ===
def requires_admin(f):
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# === ROTA: LOGIN ===
@app.route("/", methods=["GET", "POST"])
def login():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if request.method == "POST":
        # Verifica limite de tentativas
        if not verificar_rate_limit(client_ip):
            return "❌ Muitas tentativas. Tente novamente em 15 minutos.", 429

        senha_bruta = request.form.get("password", "")
        senha = sanitizar_senha(senha_bruta)
        registrar_tentativa(client_ip)

        if not senha or len(senha) < 4:
            return "❌ Credenciais inválidas.", 401

        if check_password_hash(ADMIN_PASSWORD_HASH, senha):
            session.permanent = True
            session["admin"] = True
            session["login_time"] = datetime.now().isoformat()
            # Limpa tentativas após sucesso
            if client_ip in tentativas_login:
                tentativas_login[client_ip] = []
            return redirect(url_for("dashboard"))
        else:
            return "❌ Credenciais inválidas.", 401

    return render_template("login.html")

# === ROTA: LOGOUT ===
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# === ROTA: DASHBOARD (com abas) ===
@app.route("/dashboard")
@requires_admin
def dashboard():
    tab = request.args.get("tab", "pagamentos")

    if tab == "metricas":
        try:
            r = requests.get(f"{POCKETBASE_URL}/api/collections/tarefas/records")
            tarefas = r.json().get("items", [])
        except:
            tarefas = []

        total = len(tarefas)
        abertas = len([t for t in tarefas if t.get("status") == "aberta"])
        pendentes = len([t for t in tarefas if t.get("status") == "pendente_pagamento"])
        recusadas = len([t for t in tarefas if t.get("status") == "recusada"])
        expiradas = len([t for t in tarefas if t.get("status") == "expirada"])

        por_cidade = {}
        por_estado = {}
        for t in tarefas:
            cidade = t.get("cidade", "Desconhecida")
            estado = t.get("estado", "XX")
            por_cidade[cidade] = por_cidade.get(cidade, 0) + 1
            por_estado[estado] = por_estado.get(estado, 0) + 1

        return render_template(
            "dashboard.html",
            tab="metricas",
            tarefas=tarefas,
            total=total,
            abertas=abertas,
            pendentes=pendentes,
            recusadas=recusadas,
            expiradas=expiradas,
            por_cidade=por_cidade,
            por_estado=por_estado
        )
    else:
        try:
            r = requests.get(
                f"{POCKETBASE_URL}/api/collections/tarefas/records",
                params={"filter": 'status="pendente_pagamento"', "expand": "contratante_id"}
            )
            tarefas = r.json().get("items", [])
        except:
            tarefas = []

        return render_template("dashboard.html", tab="pagamentos", tarefas=tarefas)

# === APROVAR/DESFAZER TAREFA ===
@app.route("/admin/aprovar/<id>")
@requires_admin
def admin_aprovar(id):
    try:
        r = requests.get(f"{POCKETBASE_URL}/api/collections/tarefas/records/{id}")
        if r.status_code != 200:
            return "Tarefa não encontrada", 404
        status_atual = r.json().get("status")
        novo_status = "pendente_pagamento" if status_atual == "aberta" else "aberta"
        requests.patch(f"{POCKETBASE_URL}/api/collections/tarefas/records/{id}", json={"status": novo_status})
        return f"✅ Status alterado para: {novo_status}", 200
    except Exception as e:
        return f"❌ Erro: {str(e)}", 500

# === BANIR/DESBANIR USUÁRIO ===
@app.route("/admin/banir/<id>")
@requires_admin
def admin_banir(id):
    try:
        r = requests.get(f"{POCKETBASE_URL}/api/collections/usuarios/records/{id}")
        if r.status_code != 200:
            return "Usuário não encontrado", 404
        status_atual = r.json().get("status")
        novo_status = "ativo" if status_atual == "banido" else "banido"
        requests.patch(f"{POCKETBASE_URL}/api/collections/usuarios/records/{id}", json={"status": novo_status})
        acao = "✅ Desbanido" if novo_status == "ativo" else "🚨 Banido"
        return acao, 200
    except Exception as e:
        return f"❌ Erro: {str(e)}", 500

# === INICIAR SERVIDOR ===
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)