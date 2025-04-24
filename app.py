from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime
import sqlite3
import smtplib
from email.mime.text import MIMEText
import config

app = Flask(__name__)
app.secret_key = 'chave_secreta'

# Configurações
ADMIN_USER = config.ADMIN_USER
ADMIN_PASS = config.ADMIN_PASS
EMAIL_USER = config.EMAIL_USER
EMAIL_PASS = config.EMAIL_PASS
SMTP_SERVER = config.SMTP_SERVER
SMTP_PORT = config.SMTP_PORT

# ----- Banco de Dados -----
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
        semana INTEGER NOT NULL,
        matricula TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def consulta_por_email_ou_matricula(email, matricula, semana):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes WHERE (email = ? OR matricula = ?) AND semana = ?', 
              (email, matricula, semana))
    consulta = c.fetchone()
    conn.close()
    return consulta

def marcacao_existente_no_dia(email, matricula, data, horario):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''SELECT * FROM marcacoes 
                 WHERE (email = ? OR matricula = ?) AND data = ? AND horario = ?''', 
              (email, matricula, data, horario))
    consulta = c.fetchone()
    conn.close()
    return consulta is not None

def salvar_marcacao(nome, email, matricula, data, horario, semana):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''
    INSERT INTO marcacoes (nome, email, matricula, data, horario, semana) 
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (nome, email, matricula, data, horario, semana))
    conn.commit()
    conn.close()

def get_all_consultas():
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes')
    consultas = c.fetchall()
    conn.close()
    return consultas

def get_consultas_por_data(data):
    conn = sqlite3.connect('consultas.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM marcacoes WHERE data = ? ORDER BY horario', (data,))
    consultas = cursor.fetchall()
    conn.close()
    return consultas

def excluir_consulta(consulta_id):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('DELETE FROM marcacoes WHERE id = ?', (consulta_id,))
    conn.commit()
    conn.close()

def horarios_ocupados(data):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT horario FROM marcacoes WHERE data = ?', (data,))
    horarios = c.fetchall()
    conn.close()
    return [h[0] for h in horarios]

def data_valida(data):
    data_obj = datetime.strptime(data, '%Y-%m-%d')
    return data_obj.weekday() < 5

def enviar_email_confirmacao(email, data, horario):
    msg = MIMEText(f'Sua consulta foi agendada para o dia {data} às {horario}.')
    msg['Subject'] = 'Confirmação de Consulta'
    msg['From'] = EMAIL_USER
    msg['To'] = email
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(msg['From'], [msg['To']], msg.as_string())
        server.quit()
    except Exception as e:
        print(f'Erro ao enviar o e-mail: {e}')

# ----- Rotas -----
@app.route('/', methods=['GET', 'POST'])
def marcacao():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        matricula = request.form['matricula']
        data = request.form['data']
        horario = request.form['horario']

        if not matricula.isdigit() or not (4 <= len(matricula) <= 8):
            return render_template('erro.html', mensagem="A matrícula deve conter entre 4 e 8 números.")
        
        if not data_valida(data):
            return render_template('erro.html', mensagem="Não é possível agendar para sábados ou domingos.")
        
        semana_atual = datetime.strptime(data, '%Y-%m-%d').isocalendar()[1]

        # Verifica se já existe consulta com mesmo email OU mesma matrícula na semana
        consulta_existente = consulta_por_email_ou_matricula(email, matricula, semana_atual)
        if consulta_existente:
            if consulta_existente[2] == email:  # Email igual
                return render_template('erro.html', mensagem="Este e-mail já possui uma consulta agendada nesta semana.")
            else:  # Matrícula igual
                return render_template('erro.html', mensagem="Esta matrícula já possui uma consulta agendada nesta semana.")
        
        if marcacao_existente_no_dia(email, matricula, data, horario):
            return render_template('erro.html', mensagem="Já existe uma marcação para este horário.")

        session['consulta'] = {
            'nome': nome, 'email': email, 'matricula': matricula, 
            'data': data, 'horario': horario
        }
        return redirect(url_for('confirmacao'))
    
    return render_template('marcacao.html')

@app.route('/get_horarios_disponiveis')
def get_horarios_disponiveis():
    data = request.args.get('data')
    if not data:
        return jsonify([])

    try:
        data_obj = datetime.strptime(data, '%Y-%m-%d')
        if data_obj.weekday() >= 5:
            return jsonify({'error': 'Não é possível agendar para sábados ou domingos.'})
    except ValueError:
        return jsonify({'error': 'Data inválida.'})

    todos_horarios = ["08:00", "09:00", "10:00", "11:00", "13:00", "14:00", "15:00"]
    ocupados = horarios_ocupados(data)
    disponiveis = [h for h in todos_horarios if h not in ocupados]
    return jsonify(disponiveis)

@app.route('/confirmacao', methods=['GET', 'POST'])
def confirmacao():
    if 'consulta' not in session:
        return redirect(url_for('marcacao'))

    consulta = session['consulta']

    if request.method == 'POST':
        if request.form['confirmar'] == 'true':
            semana = datetime.strptime(consulta['data'], '%Y-%m-%d').isocalendar()[1]
            salvar_marcacao(consulta['nome'], consulta['email'], consulta['matricula'], consulta['data'], consulta['horario'], semana)
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

    filtro_data = request.args.get('filtro_data')
    consultas = get_consultas_por_data(filtro_data) if filtro_data else get_all_consultas()
    return render_template('administracao.html', consultas=consultas, filtro_data=filtro_data)

@app.route('/admin/excluir', methods=['POST'])
def excluir():
    if 'admin' not in session:
        return redirect(url_for('login'))

    consulta_id = int(request.form['id'])
    filtro_data = request.form.get('filtro_data')
    excluir_consulta(consulta_id)
    if filtro_data:
        return redirect(url_for('admin', filtro_data=filtro_data))
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
    init_db()
    app.run(debug=True)