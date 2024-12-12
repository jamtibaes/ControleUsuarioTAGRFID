from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, make_response
from flask_login import LoginManager, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash 
from forms import LoginForm, CadastroUsuarioForm
from flask_wtf.csrf import CSRFProtect
from database import db
from models import Associacao, Usuario, Equipamento
from datetime import datetime
from soti import alterar_pasta_soti, cadastro_usuario_soti
from dateutil import tz
from dotenv import load_dotenv

import os
import logging
import socket
import threading

load_dotenv()
app = Flask(__name__)

# Configuração do banco de dados
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS")

# Configuração da chave secreta
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Gera uma chave aleatória toda vez (não persiste entre execuções)

# Inicializa o banco de dados com a aplicação
db.init_app(app)

# Defina o IP e porta do leitor RFID
READER_IP = os.getenv("READER_IP")
READER_PORT = int(os.getenv("READER_PORT"))

# Variável global para armazenar as tags lidas
tags_lidas = set()
buffer = ""
reading_active = True
usuarios = []

csrf = CSRFProtect(app)

# Configuração do log
logging.basicConfig(filename="record.log", level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

# Configuração de login
login_manager = LoginManager()
login_manager.init_app(app)

### RFID ###
# Função para processar os dados da tag e formatá-los corretamente
def process_tag_data(tag_data):
    tag_lines = tag_data.split('0x')
    for line in tag_lines:
        line = line.strip()
        if line and f"0x{line}" not in tags_lidas:
            formatted_tag = f"0x{line}"
            tags_lidas.add(formatted_tag)

# Função para ler os dados do leitor RFID
def listen_rfid():
    global reading_active, buffer
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((READER_IP, READER_PORT))
        while reading_active:
            data = s.recv(1024).decode('utf-8').strip()
            if not data:
                continue
            buffer += data
            while '0x' in buffer:
                try:
                    tag_data, buffer = buffer.split('0x', 1)
                    tag_data = '0x' + tag_data
                    process_tag_data(tag_data)
                except ValueError:
                    break

# Função para iniciar a leitura do RFID em uma thread separada
def start_rfid_thread():
    threading.Thread(target=listen_rfid).start()

# Rota para buscar as tags lidas
@app.route('/tags')
def get_tags():
    #alterar_pasta_soti("990011943357565", "operador")
    return jsonify(list(tags_lidas))


### LOGIN ###
# Função para carregar o usuário - FLASH-LOGIN
@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.filter_by(id=user_id, perfil="adm").first()

# Função com a rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    formulario = LoginForm(request.form)
    if request.method == 'POST' and formulario.validate():
        usuario = Usuario.query.filter_by(nome=formulario.nome.data).first()
        if usuario and check_password_hash(usuario.senha, formulario.senha.data):
            login_user(usuario)
            return redirect(url_for('dashboard'))
        else:
            flash("Usuário ou Senha não reconhecido pelo sistema.", "danger")
        return redirect(url_for('login'))
    return render_template('login.html', form=formulario)

# Função com a rota de logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Função para redirecionar usuários não logados
@login_manager.unauthorized_handler
def unauthorized():
    return redirect(url_for('login'))


### COLETOR ###
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        codigo_operador = request.form['codigo_operador']
        tag_rfid = request.form['tag_rfid']

        # Verifica se o operador existe e é do tipo "operador"
        operador = Usuario.query.filter_by(cadastro_interno=codigo_operador, perfil="operador").first()
        if not operador:
            flash("Código do operador inválido ou usuário não é do tipo operador.", "danger")
            return redirect(url_for('index'))

        # Verifica se o equipamento existe no banco de dados
        equipamento = Equipamento.query.filter_by(tag_rfid=tag_rfid).first()
        if not equipamento:
            flash("Equipamento com a tag especificada não encontrado.", "danger")
            return redirect(url_for('index'))

        # Define o timezone do Brasil (UTC-3)
        timezone_br = tz.gettz('America/Sao_Paulo')

        # Obtém o horário atual no timezone do Brasil
        timestamp = datetime.now(tz=timezone_br)

        # Cria a associação
        associacao = Associacao(usuario_id=operador.id, equipamento_id=equipamento.id, timestamp=timestamp)
        db.session.add(associacao)
        db.session.commit()

        # Muda perfil do SOTI para operador
        alterar_pasta_soti(equipamento.patrimonio, "operador")
        cadastro_usuario_soti(equipamento.patrimonio, "OPERADOR", operador.cadastro_interno)

        cookie = make_response(redirect(url_for('logado')))
        cookie.set_cookie("equipamento", value=equipamento.patrimonio)

        app.logger.info(f"Usuário: {operador.cadastro_interno} - Equipamento: {equipamento.patrimonio}")

        return cookie

    # GET request: carregar a página com as tags disponíveis
    equipamentos = Equipamento.query.all()

    cookie = request.cookies.get("equipamento")

    return render_template('associar_operador_equipamento.html', equipamentos=equipamentos, patrimonio_cookie=cookie)





    global tags_lidas
    tags_lidas.clear()
    return jsonify({"status": "reading restarted"})

# Rota para mensagem de logado
@app.route('/logado')
def logado():
    return render_template('logado.html')

# Rota para mensagem de deslogado
@app.route('/deslogado')
def deslogado():
    return render_template('deslogado.html')


### DASHBOARD ###
# DASHBOARD
# Rota para dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    total_usuarios = Usuario.query.count()
    total_equipamentos = Equipamento.query.count()
    total_associacoes = Associacao.query.count()
    associacoes = Associacao.query.all()
    return render_template('dashboard.html', 
                           total_usuarios=total_usuarios, 
                           total_equipamentos=total_equipamentos, 
                           total_associacoes=total_associacoes, 
                           associacoes=associacoes)


# USUÁRIOS
# Rota para dashboard
@app.route('/usuarios')
@login_required
def usuarios():
    usuarios = Usuario.query.all()
    return render_template('usuarios.html', usuarios=usuarios)

# Rota para excluir um usuário
@app.route('/excluir_usuario/<int:id>', methods=['POST'])
def excluir_usuario(id):
    usuario = Usuario.query.get(id)
    db.session.delete(usuario)
    db.session.commit()
    return redirect(url_for('usuarios'))

# Rota para criar usuário
@app.route('/cadastro_usuario', methods=['GET', 'POST'])
def cadastro_usuario():

    form = CadastroUsuarioForm(request.form)
    if request.method == 'POST' and form.validate():
        nome = form.nome.data
        email = form.email.data
        cpf = form.cpf.data
        cadastro_interno = form.cadastro_interno.data
        perfil = form.perfil.data
        senha_criptografada = generate_password_hash(form.senha.data)

        # Verifica duplicidade de e-mail, CPF e cadastro interno
        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já está cadastrado.', 'danger')
            return redirect(url_for('cadastro_usuario'))

        if Usuario.query.filter_by(cpf=cpf).first():
            flash('CPF já está cadastrado.', 'danger')
            return redirect(url_for('cadastro_usuario'))

        if Usuario.query.filter_by(cadastro_interno=cadastro_interno).first():
            flash('Cadastro interno já está cadastrado.', 'danger')
            return redirect(url_for('cadastro_usuario'))
        
        usuario = Usuario(nome=nome, email=email, cpf=cpf, cadastro_interno=cadastro_interno, perfil=perfil, senha=senha_criptografada)
        db.session.add(usuario)
        db.session.commit()
        flash('Usuário cadastrado com sucesso!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('cadastro_usuario.html', form=form)


@app.route('/associar', methods=['POST'])
def associar():
    usuario_id = request.form['usuario_id']
    equipamento_id = request.form['equipamento_id']
    associacao = Associacao(usuario_id=usuario_id, equipamento_id=equipamento_id)
    db.session.add(associacao)
    db.session.commit()
    return redirect(url_for('dashboard'))


@app.route('/desassociar/<int:id>', methods=['POST'])
def desassociar(id):
    associacao = Associacao.query.get_or_404(id)
    equipamento = Equipamento.query.filter_by(id=associacao.equipamento_id).first()
    # Muda perfil do SOTI para operador
    alterar_pasta_soti(equipamento.patrimonio, "administrador")
    cadastro_usuario_soti(equipamento.patrimonio, "OPERADOR", "")
    db.session.delete(associacao)
    db.session.commit()
    return redirect(url_for('dashboard'))


# EQUIPAMENTOS
@app.route('/equipamentos')
@login_required
def equipamentos():
    equipamentos = Equipamento.query.all()
    return render_template('equipamentos.html', equipamentos=equipamentos)

@app.route('/desassociacao', methods=['GET', 'POST'])
def desassociacao():
    patrimonio_cookie = request.cookies.get("equipamento")
    if not patrimonio_cookie:
        print("Não capturei cookie")
        #CRIAR UMA ROTA PARA 
        #return redirect(url_for('index'))
    if request.method == 'POST':
        associacao = Associacao.query.join(Equipamento).filter(Equipamento.patrimonio == patrimonio_cookie).first()
        if associacao:
            db.session.delete(associacao)
            db.session.commit()
            # Muda perfil do SOTI para operador
            alterar_pasta_soti(patrimonio_cookie, "administrador")
            cadastro_usuario_soti(patrimonio_cookie, "OPERADOR", "")
            return redirect(url_for('deslogado'))
        else:
            return redirect(url_for('desassociacao'))
    return render_template('desassociacao.html', patrimonio=patrimonio_cookie)



@app.route('/cadastro_equipamento', methods=['GET', 'POST'])
def cadastro_equipamento():
    if request.method == 'POST':
        numero_serie = request.form['numeroSerie']
        part_number = request.form['partNumber']
        patrimonio = request.form['patrimonio']
        tag_rfid = request.form['numeroTag']
        equipamento = Equipamento(numero_serie=numero_serie, part_number=part_number, patrimonio=patrimonio, tag_rfid=tag_rfid)
        db.session.add(equipamento)
        db.session.commit()
        cookie = make_response(redirect(url_for('dashboard')))
        cookie.set_cookie("equipamento", value=patrimonio)
        return cookie
    return render_template('cadastro_equipamento.html', tags=list(tags_lidas))



## RESIDUAL
'''
@app.route('/cadastrar', methods=['POST'])
def cadastrar():
    nome = request.form['nome']
    registro = request.form['registro']
    tag = request.form['tag']
    horario = datetime.now().strftime('%d/%m/%Y %H:%M')  # Captura o horário de cadastro
    usuarios.append({'nome': nome, 'registro': registro, 'tag': tag, 'horario': horario})
    return redirect(url_for('index'))
'''


if __name__ == '__main__':
    start_rfid_thread()
    #with app.app_context():  # Garante que o contexto da aplicação é aberto
    #   db.create_all()  # Cria as tabelas no banco de dados
    app.run(debug=True, host="0.0.0.0")
