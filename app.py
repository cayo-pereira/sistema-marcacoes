from flask import Flask, render_template, request, redirect, url_for, session, jsonify
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
     # Adicionar a coluna 'matricula' caso o banco já exista
    c.execute("PRAGMA table_info(marcacoes)")
    colunas = [coluna[1] for coluna in c.fetchall()]
    if 'matricula' not in colunas:
        c.execute("ALTER TABLE marcacoes ADD COLUMN matricula TEXT NOT NULL")
    
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
def salvar_marcacao(nome, email, matricula, data, horario, semana):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''
    INSERT INTO marcacoes (nome, email, matricula, data, horario, semana) 
    VALUES (?, ?, ?, ?, ?, ?)
    ''', (nome, email, matricula, data, horario, semana))
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

# Função para verificar horários ocupados
def horarios_ocupados(data):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT horario FROM marcacoes WHERE data = ?', (data,))
    horarios = c.fetchall()
    conn.close()
    return [horario[0] for horario in horarios]

# Função para verificar se a data é válida (segunda a sexta-feira)
def data_valida(data):
    data_selecionada = datetime.strptime(data, '%Y-%m-%d')
    return data_selecionada.weekday() < 5  # 0-4 representa segunda a sexta-feira

@app.route('/', methods=['GET', 'POST'])
def marcacao():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        matricula = request.form['matricula']
        data = request.form['data']
        horario = request.form['horario']

        # Validação da matrícula (4 a 8 números)
        if not matricula.isdigit() or not (4 <= len(matricula) <= 8):
            return render_template('erro.html', mensagem="A matrícula deve conter entre 4 e 8 números.")

        # Calcular a semana do ano
        semana_atual = datetime.strptime(data, '%Y-%m-%d').isocalendar()[1]

        # Verificar se a data é válida (não permite sábado e domingo)
        if not data_valida(data):
            return render_template('erro.html', mensagem="Não é possível agendar para sábados ou domingos.")

        # Verificar se a consulta já foi marcada na mesma semana e com o mesmo e-mail
        if consulta_ja_marcada(nome, email, semana_atual):
            return render_template('erro.html', mensagem="Você já marcou uma consulta essa semana.")

        # Armazenar a marcação
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
    
    # Verificar se a data é válida
    try:
        data_obj = datetime.strptime(data, '%Y-%m-%d')
        if data_obj.weekday() >= 5:  # Sábado (5) ou Domingo (6)
            return jsonify({'error': 'Não é possível agendar para sábados ou domingos.'})
    except ValueError:
        return jsonify({'error': 'Data inválida.'})
    
    # Horários fixos disponíveis
    todos_horarios = ["08:00", "09:00", "10:00", "11:00", "13:00", "14:00", "15:00"]
    
    # Horários já marcados
    horarios_ocupados_lista = horarios_ocupados(data)
    
    # Filtrar horários disponíveis
    horarios_disponiveis = [h for h in todos_horarios if h not in horarios_ocupados_lista]
    
    return jsonify(horarios_disponiveis)

@app.route('/confirmacao', methods=['GET', 'POST'])
def confirmacao():
    if 'consulta' not in session:
        return redirect(url_for('marcacao'))
    
    consulta = session['consulta']

    if request.method == 'POST':
        if request.form['confirmar'] == 'true':
            # Salvar a marcação no banco de dados
            semana_atual = datetime.strptime(consulta['data'], '%Y-%m-%d').isocalendar()[1]
            salvar_marcacao(consulta['nome'], consulta['email'], consulta['matricula'], consulta['data'], consulta['horario'], semana_atual)
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