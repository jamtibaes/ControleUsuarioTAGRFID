from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp

class LoginForm(FlaskForm):
    nome = StringField('Usuario', validators=[DataRequired()])
    senha = PasswordField('Senha', validators=[DataRequired()])
    entrar = SubmitField('Entrar')
    
class CadastroUsuarioForm(FlaskForm):
    nome = StringField('Usuário', validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField('E-mail', validators=[DataRequired(), Email()])
    cpf = StringField('CPF', validators=[
        DataRequired(),
        Regexp(r'^\d{3}\.\d{3}\.\d{3}-\d{2}$', message="CPF deve estar no formato 123.456.789-10")
    ])
    senha = PasswordField('Senha', validators=[
        DataRequired(),
        Length(min=4, max=100, message="A senha deve ter pelo menos 4 caracteres."),
        EqualTo('confirmacao_senha', message="As senhas devem coincidir.")
    ])
    confirmacao_senha = PasswordField('Confirmação de Senha', validators=[DataRequired()])
    cadastro_interno = StringField('Cadastro Interno', validators=[DataRequired(), Length(min=1, max=50)])
    perfil = SelectField('Perfil', choices=[('adm', 'Administrador'), ('operador', 'Operador')], validators=[DataRequired()])
    cadastrar = SubmitField('Cadastrar')





