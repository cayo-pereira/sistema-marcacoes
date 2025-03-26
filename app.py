from flask import Flask, render_template, request, redirect, url_for, session
from datetime import datetime
import sqlite3
import smtplib
from email.mime.text import MIMEText
import config  # Importa as configurações do arquivo config.py

app = Flask(__name__)
app.secret_key = 'chave_secreta'

# Usando as variáveis de configuração do arquivo config.py
ADMIN_USER = config.ADMIN_USER
ADMIN_PASS = config.ADMIN_PASS
EMAIL_USER = config.EMAIL_USER
EMAIL_PASS = config.EMAIL_PASS
SMTP_SERVER = config.SMTP_SERVER
SMTP_PORT = config.SMTP_PORT

# Função para inicializar o banco de dados
def init_db():
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS marcacoes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        email TEXT NOT NULL,
        data TEXT NOT NULL,
        horario TEXT NOT NULL,
        semana INTEGER NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

# Função para verificar se o funcionário já marcou consulta na mesma semana
def consulta_ja_marcada(nome, email, semana):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes WHERE email = ? AND semana = ?', (email, semana))
    consulta = c.fetchone()
    conn.close()
    return consulta is not None

# Função para salvar a marcação no banco de dados
def salvar_marcacao(nome, email, data, horario, semana):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''
    INSERT INTO marcacoes (nome, email, data, horario, semana) 
    VALUES (?, ?, ?, ?, ?)
    ''', (nome, email, data, horario, semana))
    conn.commit()
    conn.close()

# Função para pegar todas as consultas para a administração
def get_all_consultas():
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes')
    consultas = c.fetchall()
    conn.close()
    return consultas

# Função para excluir uma consulta do banco de dados
def excluir_consulta(consulta_id):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('DELETE FROM marcacoes WHERE id = ?', (consulta_id,))
    conn.commit()
    conn.close()

# Função para enviar o email de confirmação
def enviar_email_confirmacao(email, data, horario):
    msg = MIMEText(f'Sua consulta foi agendada para o dia {data} às {horario}.')
    msg['Subject'] = 'Confirmação de Consulta'
    msg['From'] = EMAIL_USER  # Usando a variável de configuração para o e-mail
    msg['To'] = email

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)  # Usando a variável de configuração para o servidor e porta SMTP
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)  # Usando as variáveis de configuração para login
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        server.quit()
    except Exception as e:
        print(f'Erro ao enviar o e-mail: {e}')

@app.route('/', methods=['GET', 'POST'])
def marcacao():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        data = request.form['data']
        horario = request.form['horario']

        # Calcular a semana do ano
        semana_atual = datetime.strptime(data, '%Y-%m-%d').isocalendar()[1]

        # Verificar se a consulta já foi marcada na mesma semana e com o mesmo e-mail
        if consulta_ja_marcada(nome, email, semana_atual):
            return render_template('erro.html', mensagem="Você já marcou uma consulta essa semana.")

        # Armazenar a marcação
        session['consulta'] = {'nome': nome, 'email': email, 'data': data, 'horario': horario}
        return redirect(url_for('confirmacao'))
    
    return render_template('marcacao.html')

@app.route('/confirmacao', methods=['GET', 'POST'])
def confirmacao():
    if 'consulta' not in session:
        return redirect(url_for('marcacao'))
    
    consulta = session['consulta']

    if request.method == 'POST':
        if request.form['confirmar'] == 'true':
            # Salvar a marcação no banco de dados
            semana_atual = datetime.strptime(consulta['data'], '%Y-%m-%d').isocalendar()[1]
            salvar_marcacao(consulta['nome'], consulta['email'], consulta['data'], consulta['horario'], semana_atual)
            enviar_email_confirmacao(consulta['email'], consulta['data'], consulta['horario'])
            session.pop('consulta')
            return redirect(url_for('sucesso', data=consulta['data'], horario=consulta['horario']))
        else:
            session.pop('consulta')
            return redirect(url_for('marcacao'))
    
    return render_template('confirmacao.html', **consulta)

@app.route('/sucesso')
def sucesso():
    data = request.args.get('data', 'Data não disponível')
    horario = request.args.get('horario', 'Horário não disponível')
    return render_template('sucesso.html', data=data, horario=horario)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    consultas = get_all_consultas()
    return render_template('administracao.html', consultas=consultas)

@app.route('/admin/excluir', methods=['POST'])
def excluir():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    consulta_id = int(request.form['id'])
    excluir_consulta(consulta_id)
    return redirect(url_for('admin'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']
        senha = request.form['senha']
        if usuario == ADMIN_USER and senha == ADMIN_PASS:
            session['admin'] = True
            return redirect(url_for('admin'))
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Inicializa o banco de dados ao iniciar a aplicação
    app.run(debug=True)
