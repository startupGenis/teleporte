# app.py
# TelePorte Backend
# - Flask + SQLite3
# - Web + Flutter
# - Geolocalização de fotos
# - Pix para aprovação
# - Segurança com hash
# - Desenvolvido por Genis R Lopes
# - Especialista em Python, Flutter e Startup

from flask import Flask, request, render_template, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
import sqlite3
import os
import uuid
from geopy.geocoders import Nominatim
import folium
import re


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "mudar_em_producao")
app.permanent_session_lifetime = timedelta(minutes=30)

# === DATABASE ===
DATABASE = 'teleporte.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            nome TEXT NOT NULL,
            tipo TEXT NOT NULL,
            cep TEXT NOT NULL,
            telefone TEXT NOT NULL,
            cidade TEXT NOT NULL,
            estado TEXT NOT NULL,
            maior_18 INTEGER NOT NULL,
            foto_perfil TEXT,
            status TEXT DEFAULT 'ativo',
            confianca INTEGER DEFAULT 3,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        conn.execute('''CREATE TABLE IF NOT EXISTS tarefas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo TEXT NOT NULL,
            descricao TEXT,
            endereco TEXT NOT NULL,
            lat REAL NOT NULL,
            lng REAL NOT NULL,
            raio INTEGER NOT NULL,
            preco REAL NOT NULL,
            prazo TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'pendente_pagamento',
            contratante_id INTEGER,
            prestador_id INTEGER,
            mapa_url TEXT,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (contratante_id) REFERENCES usuarios (id),
            FOREIGN KEY (prestador_id) REFERENCES usuarios (id)
        )''')

        conn.execute('''CREATE TABLE IF NOT EXISTS provas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarefa_id INTEGER NOT NULL,
            foto_url TEXT NOT NULL,
            geotag_lat REAL NOT NULL,
            geotag_lng REAL NOT NULL,
            timestamp_foto TIMESTAMP NOT NULL,
            enviado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pendente',
            FOREIGN KEY (tarefa_id) REFERENCES tarefas (id)
        )''')

        conn.execute('''CREATE TABLE IF NOT EXISTS pagamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarefa_id INTEGER NOT NULL,
            valor REAL NOT NULL,
            chave_pix TEXT NOT NULL,
            comprovante_url TEXT NOT NULL,
            status TEXT DEFAULT 'pendente',
            processado_em TIMESTAMP,
            FOREIGN KEY (tarefa_id) REFERENCES tarefas (id)
        )''')

init_db()

# === SENHA DO ADMIN ===
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH") or 'pbkdf2:sha256:600000$twC5pLncNlSkKimf$d3deecfc900d244f3255e959c2c7c95a57f136554363878c661166ab61e5bdda'

# === RATE LIMIT ===
tentativas_login = {}
MAX_TENTATIVAS = 5
JANELA_MINUTOS = 15

def verificar_rate_limit(ip: str) -> bool:
    agora = datetime.now()
    if ip not in tentativas_login:
        tentativas_login[ip] = []
    tentativas_login[ip] = [t for t in tentativas_login[ip] if agora - t < timedelta(minutes=JANELA_MINUTOS)]
    return len(tentativas_login[ip]) < MAX_TENTATIVAS

def registrar_tentativa(ip: str):
    tentativas_login.setdefault(ip, []).append(datetime.now())

# === PROTEÇÃO DE ROTAS ===
def requires_admin(f):
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("adm_login"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def requires_user(f):
    def decorated(*args, **kwargs):
        if not session.get("usuario_id"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# === ROTAS PÚBLICAS ===
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/cadastro")
def cadastro():
    return render_template("cadastro.html")

@app.route("/privacidade")
def privacidade():
    return render_template("privacidade.html")

@app.route("/investidores")
def investidores():
    return render_template("investidores.html")

# === CADASTRO DE USUÁRIO ===
@app.route("/api/usuarios", methods=["POST"])
def api_cadastrar():
    data = request.json
    required = ["email", "senha", "nome", "tipo", "cep", "telefone", "cidade", "estado", "maior_18"]
    if not all(data.get(k) for k in required):
        return jsonify({"erro": "Campos obrigatórios faltando"}), 400

    try:
        senha_hash = generate_password_hash(data["senha"])
        with get_db() as conn:
            conn.execute('''INSERT INTO usuarios 
                (email, senha, nome, tipo, cep, telefone, cidade, estado, maior_18, status) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ativo')''',
                (data["email"], senha_hash, data["nome"], data["tipo"],
                 data["cep"], data["telefone"], data["cidade"], data["estado"], data["maior_18"]))
        return jsonify({"mensagem": "Cadastro realizado com sucesso!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"erro": "E-mail já cadastrado"}), 409
    except Exception as e:
        return jsonify({"erro": str(e)}), 500

# === LOGIN DE USUÁRIO ===
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email") or (request.get_json() or {}).get("email")
        senha = request.form.get("password") or (request.get_json() or {}).get("password")

        if not email or not senha:
            return "❌ Credenciais inválidas.", 401

        with get_db() as conn:
            user = conn.execute("SELECT * FROM usuarios WHERE email = ? AND status = 'ativo'", (email,)).fetchone()

        if user and check_password_hash(user['senha'], senha):
            session["usuario_id"] = user['id']
            session["usuario_nome"] = user['nome']
            return redirect(url_for("dashboard_cliente"))
        else:
            return "❌ Credenciais inválidas.", 401

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# === DASHBOARD DO CLIENTE ===
@app.route("/dashboard")
@requires_user
def dashboard_cliente():
    return render_template("dashboard_cliente.html", nome_usuario=session.get("usuario_nome"))

# === API: Minhas Tarefas ===
@app.route('/api/tarefas/me', methods=['GET'])
@requires_user
def api_minhas_tarefas():
    with get_db() as conn:
        tarefas = [dict(row) for row in conn.execute("""
            SELECT id, titulo, endereco, preco, status, prazo, lat, lng
            FROM tarefas
            WHERE contratante_id = ?
            ORDER BY criado_em DESC
        """, (session['usuario_id'],)).fetchall()]
    return jsonify(tarefas)

# === API: Geocodificação + Mapa com Folium ===
@app.route('/api/mapa', methods=['POST'])
def api_mapa():
    data = request.json
    endereco = data.get('endereco')
    if not endereco:
        return jsonify({"erro": "Endereço é obrigatório"}), 400

    geolocator = Nominatim(user_agent="teleporte")
    location = geolocator.geocode(endereco)
    if not location:
        return jsonify({"erro": "Endereço não encontrado"}), 404

    # Gera mapa com folium
    mapa = folium.Map(location=[location.latitude, location.longitude], zoom_start=15)
    folium.Marker(
        [location.latitude, location.longitude],
        popup=location.address,
        icon=folium.Icon(color='blue', icon='info-sign')
    ).add_to(mapa)
    mapa_html = mapa._repr_html_()

    return jsonify({
        "endereco": endereco,
        "lat": location.latitude,
        "lng": location.longitude,
        "mapa": mapa_html
    })

# === API: Criar Tarefa ===
@app.route('/api/tarefas', methods=['POST'])
@requires_user
def api_criar_tarefa():
    data = request.json
    # ✅ Corrigido: removido campos não obrigatórios da verificação
    required = ['titulo', 'lat', 'lng', 'raio', 'preco', 'prazo']
    if not all(data.get(k) for k in required):
        return jsonify({"erro": "Campos obrigatórios faltando"}), 400

    try:
        with get_db() as conn:
            cursor = conn.execute('''INSERT INTO tarefas 
                (titulo, descricao, endereco, lat, lng, raio, preco, prazo, status, contratante_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pendente_pagamento', ?)''',
                (data['titulo'], data.get('descricao', ''), data.get('endereco', ''),
                 data['lat'], data['lng'], data['raio'],
                 data['preco'], data['prazo'], session['usuario_id']))
            tarefa_id = cursor.lastrowid
        return jsonify({
            "mensagem": "Tarefa criada! Gere o Pix para aprovar.",
            "tarefa_id": tarefa_id
        }), 201
    except Exception as e:
        return jsonify({"erro": str(e)}), 500

# === API: Tarefas para Prestar (próximas) ===
@app.route('/api/tarefas/prestar', methods=['GET'])
@requires_user
def api_tarefas_prestar():
    lat = request.args.get('lat', type=float)
    lng = request.args.get('lng', type=float)

    with get_db() as conn:
        if lat and lng:
            tarefas = [dict(row) for row in conn.execute("""
                SELECT id, titulo, endereco, preco, lat, lng,
                       ROUND(111.1 * SQRT(POW(lat - ?, 2) + POW(lng - ?, 2)), 1) as distancia_km
                FROM tarefas 
                WHERE status = 'aberta'
                ORDER BY distancia_km
                LIMIT 20
            """, (lat, lng)).fetchall()]
        else:
            tarefas = [dict(row) for row in conn.execute("""
                SELECT id, titulo, endereco, preco, lat, lng, 0 as distancia_km 
                FROM tarefas 
                WHERE status = 'aberta'
            """).fetchall()]
    return jsonify(tarefas)

# === API: Aceitar Tarefa ===
@app.route('/api/tarefas/aceitar/<int:id>', methods=['POST'])
@requires_user
def aceitar_tarefa(id):
    with get_db() as conn:
        tarefa = conn.execute("SELECT * FROM tarefas WHERE id = ? AND status = 'aberta'", (id,)).fetchone()
        if not tarefa:
            return jsonify({"erro": "Tarefa não encontrada ou já aceita"}), 404

        conn.execute("UPDATE tarefas SET status = 'em_andamento', prestador_id = ? WHERE id = ?", (session['usuario_id'], id))
    return jsonify({"mensagem": "Tarefa aceita com sucesso!"})

# === GERAR PIX ===
pagamentos_temp = {}

# === GERAR PIX PARA TAREFA ===
@app.route('/api/tarefas/<int:id>/gerar_pix', methods=['POST'])
@requires_user
def gerar_pix(id):
    with get_db() as conn:
        tarefa = conn.execute("""
            SELECT t.*, u.nome as contratante_nome 
            FROM tarefas t 
            JOIN usuarios u ON t.contratante_id = u.id 
            WHERE t.id = ? AND t.contratante_id = ?
        """, (id, session['usuario_id'])).fetchone()

        if not tarefa:
            return jsonify({"erro": "Tarefa não encontrada ou não autorizada"}), 404

        if tarefa['status'] != 'pendente_pagamento':
            return jsonify({"erro": "Tarefa já foi paga ou cancelada"}), 400

        valor = tarefa['preco']
        
        # Gera TXID com: teleporte-AAAAMMDD-HHMM-Titulo
        data_hora = datetime.now().strftime("%Y%m%d-%H%M")
        titulo_limpo = re.sub(r'[^a-zA-Z0-9]', '', tarefa['titulo'])[:20]
        txid = f"teleporte-{data_hora}-{titulo_limpo}".lower()

        # Dados do Pix (chave fixa do sistema)
        chave_pix = "053984797344"
        pix_copia_cola = f"PIX {valor} para {chave_pix} | Ref: {txid}"

        # Salva temporariamente (em produção, salve no banco)
        pagamentos_temp[txid] = {
            "tarefa_id": id,
            "valor": valor,
            "txid": txid,
            "chave": chave_pix,
            "copia_cola": pix_copia_cola,
            "criado_em": datetime.now(),
            "status": "pendente"
        }

        return jsonify({
            "mensagem": "Pix gerado com sucesso!",
            "pix": pix_copia_cola,
            "txid": txid,
            "valor": valor,
            "chave": chave_pix,
            "titulo": tarefa['titulo'],
            "contratante": tarefa['contratante_nome']
        }), 201

# === REPROVAR TAREFA (marca como 'recusada') ===
@app.route("/adm/reprovar/<int:id>")
@requires_admin
def adm_reprovar(id):
    try:
        with get_db() as conn:
            tarefa = conn.execute("SELECT * FROM tarefas WHERE id = ?", (id,)).fetchone()
            if not tarefa:
                return "❌ Tarefa não encontrada", 404

            conn.execute("UPDATE tarefas SET status = 'recusada' WHERE id = ?", (id,))
        return "✅ Tarefa recusada com sucesso.", 200
    except Exception as e:
        return f"❌ Erro: {str(e)}", 500


# === APROVAR TAREFA ===
@app.route("/adm/aprovar/<int:id>")
@requires_admin
def adm_aprovar(id):
    try:
        with get_db() as conn:
            tarefa = conn.execute("SELECT status FROM tarefas WHERE id = ?", (id,)).fetchone()
            if not tarefa:
                return "❌ Tarefa não encontrada", 404

            novo_status = "aberta" if tarefa['status'] == "pendente_pagamento" else "pendente_pagamento"
            conn.execute("UPDATE tarefas SET status = ? WHERE id = ?", (novo_status, id))
            return f"✅ Status alterado para: {novo_status}", 200
    except Exception as e:
        return f"❌ Erro: {str(e)}", 500

# === BANIR USUÁRIO ===
@app.route("/adm/banir/<int:id>")
@requires_admin
def adm_banir(id):
    try:
        with get_db() as conn:
            user = conn.execute("SELECT status FROM usuarios WHERE id = ?", (id,)).fetchone()
            if not user:
                return "❌ Usuário não encontrado", 404

            novo_status = "ativo" if user['status'] == "banido" else "banido"
            conn.execute("UPDATE usuarios SET status = ? WHERE id = ?", (novo_status, id))
            return f"🚨 Usuário {'desbanido' if novo_status == 'ativo' else 'banido'}", 200
    except Exception as e:
        return f"❌ Erro: {str(e)}", 500

# === LOGIN E DASHBOARD DO ADMIN ===
@app.route("/adm", methods=["GET", "POST"])
def adm_login():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    if request.method == "POST":
        if not verificar_rate_limit(client_ip):
            return "❌ Muitas tentativas. Tente novamente em 15 minutos.", 429

        senha = request.form.get("password", "")
        registrar_tentativa(client_ip)

        if not senha or len(senha) < 4:
            return "❌ Credenciais inválidas.", 401

        if check_password_hash(ADMIN_PASSWORD_HASH, senha):
            session["admin"] = True
            if client_ip in tentativas_login:
                del tentativas_login[client_ip]
            return redirect(url_for("adm_dashboard"))
        else:
            return "❌ Credenciais inválidas.", 401

    return render_template("adm_login.html")

@app.route("/adm/dashboard")
@requires_admin
def adm_dashboard():
    tab = request.args.get("tab", "pagamentos")

    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if tab == "metricas":
            # ✅ CORRIGIDO: JOIN com usuarios para pegar cidade/estado
            cursor.execute("""
                SELECT t.*, u.cidade, u.estado
                FROM tarefas t
                JOIN usuarios u ON t.contratante_id = u.id
            """)
            tarefas_db = cursor.fetchall()

            total = len(tarefas_db)
            abertas = len([t for t in tarefas_db if t['status'] == 'aberta'])
            pendentes = len([t for t in tarefas_db if t['status'] == 'pendente_pagamento'])
            recusadas = len([t for t in tarefas_db if t['status'] == 'recusada'])
            expiradas = len([t for t in tarefas_db if t['status'] == 'expirada'])

            por_cidade = {}
            por_estado = {}
            for t in tarefas_db:
                cidade = t.get('cidade') or 'Desconhecida'
                estado = t.get('estado') or 'XX'
                por_cidade[cidade] = por_cidade.get(cidade, 0) + 1
                por_estado[estado] = por_estado.get(estado, 0) + 1

            return render_template(
                "adm_dashboard.html",
                tab="metricas",
                tarefas=tarefas_db,
                total=total,
                abertas=abertas,
                pendentes=pendentes,
                recusadas=recusadas,
                expiradas=expiradas,
                por_cidade=por_cidade,
                por_estado=por_estado
            )

        else:
            # === ABA: Aprovar Pagamentos ===
            cursor.execute("""
                SELECT t.id, t.titulo, t.preco, t.status, t.contratante_id, t.criado_em,
                       strftime('%%Y-%%m-%%d %%H:%%M', t.criado_em) as criado_em_str,
                       u.nome as contratante_nome
                FROM tarefas t
                JOIN usuarios u ON t.contratante_id = u.id
                WHERE t.status = 'pendente_pagamento'
            """)
            tarefas = [dict(row) for row in cursor.fetchall()]

            cursor.execute("SELECT id FROM usuarios WHERE status = 'banido'")
            usuarios_banidos = {row['id']: True for row in cursor.fetchall()}

            return render_template(
                "adm_dashboard.html",
                tab="pagamentos",
                tarefas=tarefas,
                usuarios_banidos=usuarios_banidos
            )

# === ROTA: Trocar Senha do Admin ===
@app.route("/adm/trocar_senha", methods=["GET", "POST"])
@requires_admin
def adm_trocar_senha():
    global ADMIN_PASSWORD_HASH
    if request.method == "POST":
        senha_atual = request.form.get("senha_atual")
        nova_senha = request.form.get("nova_senha")
        confirmar_senha = request.form.get("confirmar_senha")

        if not check_password_hash(ADMIN_PASSWORD_HASH, senha_atual):
            return "❌ Senha atual incorreta.", 401

        if nova_senha != confirmar_senha:
            return "❌ As novas senhas não coincidem.", 400

        if len(nova_senha) < 6:
            return "❌ A nova senha deve ter pelo menos 6 caracteres.", 400

        # Atualiza o hash global (em memória)

        ADMIN_PASSWORD_HASH = generate_password_hash(nova_senha)

        return "✅ Senha alterada com sucesso!", 200

    return render_template("trocar_senha.html")

@app.route("/adm/logout")
def adm_logout():
    session.clear()
    return redirect(url_for("adm_login"))

# === INICIAR ===
if __name__ == "__main__":
    if not os.path.exists(DATABASE):
        print(f"❌ Arquivo {DATABASE} não encontrado. Criando...")
        init_db()
    else:
        print(f"✅ Banco {DATABASE} carregado com sucesso.")

    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)