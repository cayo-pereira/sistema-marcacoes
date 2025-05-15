from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from datetime import datetime
from openpyxl import Workbook
from io import BytesIO
import sqlite3
import config
import json

app = Flask(__name__)
app.secret_key = 'chave_secreta'

# Configurações
ADMIN_USER = config.ADMIN_USER
ADMIN_PASS = config.ADMIN_PASS

# ----- Banco de Dados -----
def init_db():
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    
    # Tabela de marcações
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
    
    # Tabela de logs de auditoria
    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id INTEGER,
        old_value TEXT,
        new_value TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL
    )
    ''')
    
    conn.commit()
    conn.close()

def log_audit(action, entity_type, entity_id=None, old_value=None, new_value=None):
    """Registra uma ação no log de auditoria"""
    try:
        conn = sqlite3.connect('consultas.db')
        c = conn.cursor()
        
        # Obtém o usuário atual (se estiver logado)
        user_id = session.get('admin', 'Anonymous')
        
        # Obtém o IP do cliente
        ip_address = request.remote_addr
        
        # Converte valores para string (se necessário)
        old_value_str = json.dumps(old_value) if old_value is not None else None
        new_value_str = json.dumps(new_value) if new_value is not None else None
        
        # Insere o log no banco de dados
        c.execute('''
        INSERT INTO audit_logs 
        (user_id, action, entity_type, entity_id, old_value, new_value, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            action,
            entity_type,
            entity_id,
            old_value_str,
            new_value_str,
            ip_address,
            datetime.now().isoformat()
        ))
        
        conn.commit()
    except Exception as e:
        print(f"Erro ao registrar log de auditoria: {e}")
    finally:
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
    consulta_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Registra no log de auditoria
    nova_marcacao = {
        'nome': nome,
        'email': email,
        'matricula': matricula,
        'data': data,
        'horario': horario,
        'semana': semana
    }
    log_audit(
        action="CREATE_APPOINTMENT",
        entity_type="Marcacao",
        entity_id=consulta_id,
        new_value=nova_marcacao
    )
    
    return consulta_id

def get_consultas_por_nome(nome):
    conn = sqlite3.connect('consultas.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM marcacoes WHERE nome LIKE ? ORDER BY data, horario', (f'%{nome}%',))
    consultas = cursor.fetchall()
    conn.close()
    return consultas

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

def get_consulta_by_id(consulta_id):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes WHERE id = ?', (consulta_id,))
    consulta = c.fetchone()
    conn.close()
    return consulta

def excluir_consulta(consulta_id):
    consulta = get_consulta_by_id(consulta_id)
    if consulta:
        # Pega o nome do admin do config.py se não estiver na sessão
        admin_user = session.get('admin_username', ADMIN_USER)  # Usa ADMIN_USER do config
        
        consulta_dict = {
            'id': consulta[0],
            'nome': consulta[1],
            'email': consulta[2],
            'data': consulta[3],
            'horario': consulta[4],
            'semana': consulta[5],
            'matricula': consulta[6],
            'deleted_by': admin_user
        }
        
        conn = sqlite3.connect('consultas.db')
        c = conn.cursor()
        c.execute('DELETE FROM marcacoes WHERE id = ?', (consulta_id,))
        conn.commit()
        conn.close()
        
        log_audit(
            action="DELETE_APPOINTMENT",
            entity_type="Marcacao",
            entity_id=consulta_id,
            old_value=consulta_dict
        )
        return True
    return False

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

def get_audit_logs(limit=100):
    """Obtém os logs de auditoria"""
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('''
    SELECT * FROM audit_logs 
    ORDER BY created_at DESC 
    LIMIT ?
    ''', (limit,))
    logs = c.fetchall()
    conn.close()
    
    # Converte para um formato mais legível
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            'id': log[0],
            'user_id': log[1],
            'action': log[2],
            'entity_type': log[3],
            'entity_id': log[4],
            'old_value': json.loads(log[5]) if log[5] else None,
            'new_value': json.loads(log[6]) if log[6] else None,
            'ip_address': log[7],
            'created_at': log[8]
        })
    
    return formatted_logs

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
    filtro_nome = request.args.get('filtro_nome')  # Novo filtro
    
    if filtro_nome:
        consultas = get_consultas_por_nome(filtro_nome)
    elif filtro_data:
        consultas = get_consultas_por_data(filtro_data)
    else:
        consultas = get_all_consultas()
        
    return render_template('administracao.html', 
                         consultas=consultas, 
                         filtro_data=filtro_data,
                         filtro_nome=filtro_nome)  # Passa o filtro_nome para o template

@app.route('/admin/excluir', methods=['POST'])
def excluir():
    if 'admin' not in session:
        return redirect(url_for('login'))

    consulta_id = int(request.form['id'])
    filtro_data = request.form.get('filtro_data')
    
    # Adiciona informação do administrador que está executando a ação
    admin_user = session.get('admin', 'Unknown')
    print(f"Admin {admin_user} está excluindo a consulta {consulta_id}")  # Log para debug
    
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
            session['admin_username'] = usuario  # Armazena o nome REAL do config.py
            log_audit(
                action="ADMIN_LOGIN",
                entity_type="User",
                new_value={'username': usuario}
            )
            return redirect(url_for('admin'))
        else:
            log_audit(
                action="FAILED_LOGIN_ATTEMPT",
                entity_type="User",
                new_value={'username': usuario}
            )
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    if 'admin' in session:
        log_audit(
            action="ADMIN_LOGOUT",
            entity_type="User",
            new_value={'username': session.get('admin_username', 'admin')}
        )
    session.clear()  # Limpa TODOS os dados da sessão
    return redirect(url_for('login'))

@app.route('/admin/logs/legend')
def log_legend():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('log_legend.html')

@app.route('/admin/logs')
def view_logs():  # Esta é a rota principal para visualizar os logs
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    logs = get_audit_logs()
    return render_template('audit_logs.html', logs=logs)

@app.route('/debug')
def debug():
    return f"""
    Admin logado: {session.get('admin', False)}<br>
    Nome do admin: {session.get('admin_username', 'Não definido')}<br>
    ADMIN_USER do config: {config.ADMIN_USER}
    """

@app.route('/admin/exportar')
def exportar_consultas():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    consultas = get_all_consultas()

    # Cria um workbook do Excel
    wb = Workbook()
    ws = wb.active
    ws.title = "Consultas"

    # Cabeçalhos
    ws.append(["Nome", "Email", "Data", "Horário", "Matrícula"])

    # Dados
    for consulta in consultas:
        ws.append([consulta[1], consulta[2], consulta[3], consulta[4], consulta[6]])

    # Salva para um buffer em memória
    output = BytesIO()
    wb.save(output)
    output.seek(0)

    # Configura a resposta
    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=consultas.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    # Log opcional
    log_audit(
        action="EXPORT_APPOINTMENTS",
        entity_type="System",
        new_value={"exported_records": len(consultas)}
    )
    
    return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True)