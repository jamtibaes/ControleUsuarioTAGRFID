from datetime import datetime
from database import db
from flask_login import UserMixin


class Usuario(UserMixin,db.Model):
    __tablename__ = 'usuarios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)  # CPF com formato 123.456.789-12
    cadastro_interno = db.Column(db.String(50), unique=True, nullable=False)
    perfil = db.Column(db.String(20), nullable=False)
    senha = db.Column(db.String(100), nullable=False)

class Equipamento(db.Model):
    __tablename__ = 'equipamentos'
    id = db.Column(db.Integer, primary_key=True)
    numero_serie = db.Column(db.String(100), unique=True, nullable=False)
    part_number = db.Column(db.String(100), nullable=False)
    patrimonio = db.Column(db.String(100), unique=True, nullable=False)
    tag_rfid = db.Column(db.String(50), unique=True, nullable=False)

class Associacao(db.Model):
    __tablename__ = 'associacoes'
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuarios.id'), unique=True)
    equipamento_id = db.Column(db.Integer, db.ForeignKey('equipamentos.id'), unique=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    usuario = db.relationship('Usuario', backref=db.backref('associacao', uselist=False))
    equipamento = db.relationship('Equipamento', backref=db.backref('associacao', uselist=False))
