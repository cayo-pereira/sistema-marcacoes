from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response
from datetime import datetime, timedelta
from openpyxl import Workbook
from io import BytesIO
import sqlite3
import config
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'chave_secreta'

DEFAULT_SETTINGS = {
    'start_time': '08:00',
    'end_time': '15:00',
    'appointment_duration': 60,
    'lunch_start_time': '12:00',
    'lunch_end_time': '13:00',
    'max_appointments_per_user': 1,
    'appointments_period_days': 7,
    'allow_weekends': False,
    'available_weekdays': "1,2,3,4,5",
    'specific_available_dates': "",
    'availability_mode': "weekdays"
}

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
        semana INTEGER NOT NULL, -- Pode ser deprecado ou recalculado com base nas novas regras
        matricula TEXT NOT NULL,
        telefone TEXT
    )
    ''')
    
    try:
        c.execute("PRAGMA table_info(marcacoes)")
        columns = [column[1] for column in c.fetchall()]
        if 'telefone' not in columns:
            c.execute("ALTER TABLE marcacoes ADD COLUMN telefone TEXT")
    except sqlite3.OperationalError as e:
        print(f"Erro ao verificar/adicionar coluna 'telefone': {e}")

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

    c.execute('''
    CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')
    
    for key, value in DEFAULT_SETTINGS.items():
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))

    conn.commit()
    conn.close()

def get_setting(key):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = c.fetchone()
    conn.close()
    if result:
        if key in ['appointment_duration', 'max_appointments_per_user', 'appointments_period_days']:
            return int(result[0])
        if key == 'allow_weekends':
            return result[0].lower() == 'true'
        return result[0]
    return DEFAULT_SETTINGS.get(key)

def update_setting(key, value):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute("UPDATE settings SET value = ? WHERE key = ?", (str(value), key))
    conn.commit()
    conn.close()
    log_audit(action="UPDATE_SETTING", entity_type="SystemSetting", new_value={'key': key, 'value': value})

def get_all_settings():
    settings = {}
    for key in DEFAULT_SETTINGS.keys():
        settings[key] = get_setting(key)
    return settings

def log_audit(action, entity_type, entity_id=None, old_value=None, new_value=None):
    conn = None
    try:
        conn = sqlite3.connect('consultas.db')
        c = conn.cursor()
        user_id = session.get('admin_username', 'Anonymous') 
        ip_address = request.remote_addr
        old_value_str = json.dumps(old_value) if old_value is not None else None
        new_value_str = json.dumps(new_value) if new_value is not None else None
        
        c.execute('''
        INSERT INTO audit_logs 
        (user_id, action, entity_type, entity_id, old_value, new_value, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, action, entity_type, entity_id, old_value_str, new_value_str, ip_address, datetime.now().isoformat()))
        conn.commit()
    except Exception as e:
        print(f"Erro ao registrar log de auditoria: {e}")
    finally:
        if conn:
            conn.close()

def consulta_por_email_ou_matricula_no_periodo(email, matricula, start_date, end_date):
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT COUNT(*) as count FROM marcacoes 
                 WHERE (email = ? OR matricula = ?) 
                 AND date(data) BETWEEN date(?) AND date(?)''', 
              (email, matricula, start_date.strftime('%Y-%m-%d'), end_date.strftime('%Y-%m-%d')))
    result = c.fetchone()
    conn.close()
    return result['count'] if result else 0

def marcacao_existente_no_horario(data, horario):
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM marcacoes WHERE data = ? AND horario = ?', (data, horario))
    consulta = c.fetchone()
    conn.close()
    return consulta is not None

def salvar_marcacao(nome, email, matricula, telefone, data, horario):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    semana_legacy = datetime.strptime(data, '%Y-%m-%d').isocalendar()[1]

    c.execute('''
    INSERT INTO marcacoes (nome, email, matricula, telefone, data, horario, semana) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (nome, email, matricula, telefone, data, horario, semana_legacy))
    consulta_id = c.lastrowid
    conn.commit()
    conn.close()
    
    nova_marcacao = {
        'nome': nome, 'email': email, 'matricula': matricula, 'telefone': telefone,
        'data': data, 'horario': horario
    }
    log_audit(action="CREATE_APPOINTMENT", entity_type="Marcacao", entity_id=consulta_id, new_value=nova_marcacao)
    return consulta_id

def get_consultas_base(admin_level='primary', query_extension="", params=()):
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    select_cols = "id, nome, email, data, horario, semana, matricula, telefone" 
    if admin_level == 'secondary':
        select_cols = "id, data, horario" 

    base_query = f'SELECT {select_cols} FROM marcacoes'
    final_query = f'{base_query} {query_extension}'

    c.execute(final_query, params)
    consultas = c.fetchall()
    conn.close()
    return consultas

def get_all_consultas(admin_level='primary'):
    return get_consultas_base(admin_level, "ORDER BY data, horario")

def get_consultas_por_nome(nome, admin_level='primary'):
    if admin_level == 'secondary':
        return get_all_consultas(admin_level)
    return get_consultas_base(admin_level, "WHERE nome LIKE ? ORDER BY data, horario", (f'%{nome}%',))

def get_consultas_por_data(data, admin_level='primary'):
    return get_consultas_base(admin_level, "WHERE data = ? ORDER BY horario", (data,))

def get_consulta_by_id(consulta_id):
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row 
    c = conn.cursor()
    c.execute('SELECT id, nome, email, data, horario, semana, matricula, telefone FROM marcacoes WHERE id = ?', (consulta_id,))
    consulta = c.fetchone()
    conn.close()
    return consulta

def excluir_consulta(consulta_id):
    consulta = get_consulta_by_id(consulta_id) 
    if consulta:
        admin_user = session.get('admin_username', config.ADMIN_USER)
        consulta_dict = dict(consulta) 
        consulta_dict['deleted_by'] = admin_user

        conn = sqlite3.connect('consultas.db')
        c = conn.cursor()
        c.execute('DELETE FROM marcacoes WHERE id = ?', (consulta_id,))
        conn.commit()
        conn.close()
        
        log_audit(action="DELETE_APPOINTMENT", entity_type="Marcacao", entity_id=consulta_id, old_value=consulta_dict)
        return True
    return False

def data_valida(data_str):
    try:
        data_obj = datetime.strptime(data_str, '%Y-%m-%d').date()
        config_mode = get_setting('availability_mode')
        
        if config_mode == 'weekdays':
            allow_weekends = get_setting('allow_weekends')
            configured_weekdays_str = get_setting('available_weekdays')
            configured_weekdays = [int(d.strip()) for d in configured_weekdays_str.split(',')]

            if not allow_weekends and data_obj.weekday() >= 5:
                return False
            
            return data_obj.weekday() in configured_weekdays
            
        elif config_mode == 'specific_dates':
            specific_dates_str = get_setting('specific_available_dates')
            if not specific_dates_str:
                return False
            
            available_dates = [datetime.strptime(d.strip(), '%Y-%m-%d').date() for d in specific_dates_str.split(',')]
            return data_obj in available_dates
            
        return False
    except ValueError:
        return False

def generate_time_slots(data_str):
    if not data_valida(data_str):
        return []

    start_time_str = get_setting('start_time')
    end_time_str = get_setting('end_time')
    duration = get_setting('appointment_duration')
    lunch_start_str = get_setting('lunch_start_time')
    lunch_end_str = get_setting('lunch_end_time')

    slots = []
    current_time = datetime.strptime(start_time_str, '%H:%M')
    end_time = datetime.strptime(end_time_str, '%H:%M')
    lunch_start = datetime.strptime(lunch_start_str, '%H:%M')
    lunch_end = datetime.strptime(lunch_end_str, '%H:%M')
    
    while current_time < end_time:
        slot_end_time = current_time + timedelta(minutes=duration)
        
        is_in_lunch = not (slot_end_time <= lunch_start or current_time >= lunch_end)
        
        if slot_end_time > end_time:
            break
            
        if not is_in_lunch:
            slots.append(current_time.strftime('%H:%M'))
            
        current_time += timedelta(minutes=duration)

    return slots


def horarios_disponiveis_para_data(data_str):
    if not data_valida(data_str):
        return {'error': 'Data inválida ou não disponível para agendamento.'}

    todos_horarios_possiveis = generate_time_slots(data_str)
    
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute('SELECT horario FROM marcacoes WHERE data = ?', (data_str,))
    ocupados_db = [h[0] for h in c.fetchall()]
    conn.close()

    disponiveis = [h for h in todos_horarios_possiveis if h not in ocupados_db]
    return disponiveis


def create_admin_user(username, password):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    try:
        hashed_password = generate_password_hash(password)
        c.execute("INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, ?)",
                  (username, hashed_password, datetime.now().isoformat()))
        user_id = c.lastrowid
        conn.commit()
        log_audit(action="CREATE_ADMIN_USER", entity_type="AdminUser", entity_id=user_id, new_value={'username': username})
        return True, "Conta criada com sucesso."
    except sqlite3.IntegrityError:
        return False, "Nome de utilizador já existe."
    except Exception as e:
        return False, f"Erro ao criar conta: {e}"
    finally:
        conn.close()

def get_secondary_admin_users():
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, username, created_at FROM admin_users ORDER BY username")
    users = c.fetchall()
    conn.close()
    return users

def delete_admin_user(user_id):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    try:
        c.execute("SELECT username FROM admin_users WHERE id = ?", (user_id,))
        user_to_delete_tuple = c.fetchone()
        
        if not user_to_delete_tuple:
            return False, "Utilizador não encontrado."

        username_to_log = user_to_delete_tuple[0] 

        c.execute("DELETE FROM admin_users WHERE id = ?", (user_id,))
        conn.commit()
        
        log_audit(
            action="DELETE_ADMIN_USER", 
            entity_type="AdminUser", 
            entity_id=user_id, 
            old_value={'username': username_to_log}
        )
        return True, "Conta de administrador secundário apagada com sucesso."
    except Exception as e:
        print(f"Erro detalhado ao apagar conta: {type(e).__name__} - {e}")
        return False, f"Erro ao apagar conta: {e}"
    finally:
        if conn:
            conn.close()

def verify_admin_user(username, password):
    conn = sqlite3.connect('consultas.db')
    c = conn.cursor()
    c.execute("SELECT password_hash FROM admin_users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result and check_password_hash(result[0], password):
        return True
    return False

@app.route('/', methods=['GET', 'POST'])
def marcacao():
    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        matricula = request.form['matricula']
        telefone = request.form.get('telefone')
        data = request.form['data']
        horario = request.form['horario']

        if not matricula.isdigit() or not (4 <= len(matricula) <= 8):
            return render_template('erro.html', mensagem="A matrícula deve conter entre 4 e 8 números.")
        
        if not data_valida(data):
            return render_template('erro.html', mensagem="Data inválida, fora do período de atendimento, ou não disponível para agendamento.")

        max_consultas = get_setting('max_appointments_per_user')
        periodo_dias = get_setting('appointments_period_days')
        
        if max_consultas > 0 and periodo_dias > 0:

            data_consulta_obj = datetime.strptime(data, '%Y-%m-%d')

            start_check_date = data_consulta_obj - timedelta(days=periodo_dias -1)
            end_check_date = data_consulta_obj

            if periodo_dias % 7 == 0:
                num_semanas = periodo_dias // 7
                if num_semanas == 1:
                    semana_consulta = data_consulta_obj.isocalendar()
                    ano_consulta, sem_consulta_num, _ = semana_consulta
                    
                    conn_temp = sqlite3.connect('consultas.db')
                    conn_temp.row_factory = sqlite3.Row
                    c_temp = conn_temp.cursor()
                    c_temp.execute('SELECT data FROM marcacoes WHERE (email = ? OR matricula = ?)', (email, matricula))
                    marcacoes_utilizador = c_temp.fetchall()
                    conn_temp.close()

                    consultas_na_mesma_semana_periodo = 0
                    for marc in marcacoes_utilizador:
                        data_m_obj = datetime.strptime(marc['data'], '%Y-%m-%d')
                        ano_m, sem_m_num, _ = data_m_obj.isocalendar()
                        if ano_m == ano_consulta and sem_m_num == sem_consulta_num:
                            consultas_na_mesma_semana_periodo +=1
                    
                    if consultas_na_mesma_semana_periodo >= max_consultas:
                        return render_template('erro.html', mensagem=f"Já atingiu o limite de {max_consultas} consulta(s) por semana.")

        if marcacao_existente_no_horario(data, horario):
            return render_template('erro.html', mensagem="Este horário acaba de ser ocupado ou é inválido.")

        session['consulta'] = {
            'nome': nome, 'email': email, 'matricula': matricula, 'telefone': telefone,
            'data': data, 'horario': horario
        }
        return redirect(url_for('confirmacao'))
    
   
    min_date_allowed = datetime.now().strftime('%Y-%m-%d')
    return render_template('marcacao.html', min_date_allowed=min_date_allowed)


@app.route('/get_horarios_disponiveis')
def get_horarios_disponiveis_route():
    data = request.args.get('data')
    if not data:
        return jsonify([])

    resultado = horarios_disponiveis_para_data(data)
    if isinstance(resultado, dict) and 'error' in resultado:
        return jsonify(resultado)
    return jsonify(resultado)


@app.route('/get_unavailable_dates_config')
def get_unavailable_dates_config():
    config = {
        'mode': get_setting('availability_mode'),
        'weekdays': get_setting('available_weekdays'),
        'specific_dates': get_setting('specific_available_dates'),
        'allow_weekends_global': get_setting('allow_weekends')
    }
    return jsonify(config)


@app.route('/confirmacao', methods=['GET', 'POST'])
def confirmacao():
    if 'consulta' not in session:
        return redirect(url_for('marcacao'))

    consulta = session['consulta']

    if request.method == 'POST':
        if request.form.get('confirmar') == 'true':
            salvar_marcacao(consulta['nome'], consulta['email'], consulta['matricula'], 
                            consulta['telefone'], consulta['data'], consulta['horario'])
            session.pop('consulta', None)
            return redirect(url_for('sucesso', data=consulta['data'], horario=consulta['horario']))
        else:
            session.pop('consulta', None)
            return redirect(url_for('marcacao'))

    return render_template('confirmacao.html', **consulta)


@app.route('/sucesso')
def sucesso():
    data = request.args.get('data', 'Data não disponível')
    horario = request.args.get('horario', 'Horário não disponível')
    return render_template('sucesso.html', data=data, horario=horario)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario_form = request.form['usuario']
        senha_form = request.form['senha']
        
        admin_level_to_set = None
        actual_username = None
        is_primary_admin = False

        if usuario_form == config.ADMIN_USER and senha_form == config.ADMIN_PASS:
            admin_level_to_set = 'primary'
            actual_username = config.ADMIN_USER
            is_primary_admin = True
        else:
            if verify_admin_user(usuario_form, senha_form):
                admin_level_to_set = 'secondary'
                actual_username = usuario_form
                is_primary_admin = False
            
        if admin_level_to_set:
            session['admin'] = True
            session['admin_username'] = actual_username 
            session['admin_level'] = admin_level_to_set
            session['is_primary_admin'] = is_primary_admin
            log_audit(action="ADMIN_LOGIN", entity_type="User", new_value={'username': actual_username, 'level': admin_level_to_set})
            return redirect(url_for('admin'))
        else:
            log_audit(action="FAILED_LOGIN_ATTEMPT", entity_type="User", new_value={'username': usuario_form})
            return render_template('login.html', erro="Utilizador ou senha inválidos.")
            
    return render_template('login.html')


@app.route('/admin', methods=['GET'])
def admin():
    if 'admin' not in session:
        return redirect(url_for('login'))

    admin_level = session.get('admin_level', 'primary') 
    is_primary = session.get('is_primary_admin', False)

    filtro_data = request.args.get('filtro_data')
    filtro_nome = request.args.get('filtro_nome')
    
    if admin_level == 'secondary' and filtro_nome:
        filtro_nome = None 

    if filtro_nome:
        consultas = get_consultas_por_nome(filtro_nome, admin_level)
    elif filtro_data:
        consultas = get_consultas_por_data(filtro_data, admin_level)
    else:
        consultas = get_all_consultas(admin_level)
        
    return render_template('administracao.html', 
                         consultas=consultas, 
                         filtro_data=filtro_data,
                         filtro_nome=filtro_nome,
                         admin_level=admin_level,
                         is_primary_admin=is_primary)


@app.route('/admin/excluir', methods=['POST'])
def excluir():
    if 'admin' not in session:
        return redirect(url_for('login'))

    consulta_id = int(request.form['id'])
    original_filtro_data = request.form.get('original_filtro_data')
    original_filtro_nome = request.form.get('original_filtro_nome')
    
    excluir_consulta(consulta_id) 
    
    redirect_args = {}
    if original_filtro_data:
        redirect_args['filtro_data'] = original_filtro_data
    if original_filtro_nome and session.get('admin_level') == 'primary':
        redirect_args['filtro_nome'] = original_filtro_nome
        
    return redirect(url_for('admin', **redirect_args))


@app.route('/logout', methods=['POST'])
def logout():
    if 'admin' in session:
        log_audit(action="ADMIN_LOGOUT", entity_type="User", new_value={'username': session.get('admin_username', 'admin_desconhecido')})
    session.clear()
    return redirect(url_for('login'))


@app.route('/admin/config', methods=['GET', 'POST'])
def config_page():
    if not session.get('admin') or not session.get('is_primary_admin'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        form_name = request.form.get('form_name')

        if form_name == 'general_settings':
            update_setting('start_time', request.form['start_time'])
            update_setting('end_time', request.form['end_time'])
            update_setting('lunch_start_time', request.form['lunch_start_time'])
            update_setting('lunch_end_time', request.form['lunch_end_time'])
            update_setting('appointment_duration', int(request.form['appointment_duration']))
        
        elif form_name == 'availability_settings':
            update_setting('availability_mode', request.form['availability_mode'])
            if request.form['availability_mode'] == 'weekdays':
                selected_weekdays = request.form.getlist('available_weekdays')
                update_setting('available_weekdays', ",".join(selected_weekdays))

            else:
                update_setting('specific_available_dates', request.form['specific_available_dates'])

        elif form_name == 'user_limit_settings':
            update_setting('max_appointments_per_user', int(request.form['max_appointments_per_user']))
            update_setting('appointments_period_days', int(request.form['appointments_period_days']))

        elif form_name == 'create_admin_user':
            username = request.form['new_admin_username']
            password = request.form['new_admin_password']
            confirm_password = request.form['new_admin_confirm_password']
            if password == confirm_password:
                success, message = create_admin_user(username, password)
                if success:
                    session['flash_message'] = message
                else:
                    session['flash_error_message'] = message
            else:
                session['flash_error_message'] = "As senhas não coincidem."
        
        return redirect(url_for('config_page'))

    current_settings = get_all_settings()
    secondary_users = get_secondary_admin_users()
    

    flash_message = session.pop('flash_message', None)
    flash_error_message = session.pop('flash_error_message', None)

    duration_options = []
    for mins in range(10, 121, 10):
        hours = mins // 60
        rem_mins = mins % 60
        label = ""
        if hours > 0:
            label += f"{hours}h"
        if rem_mins > 0:
            if hours > 0: label += " "
            label += f"{rem_mins}min"
        if not label:
            label = f"{mins}min"
        duration_options.append({'value': mins, 'label': label})


    return render_template('config.html', settings=current_settings, 
                                          secondary_users=secondary_users,
                                          flash_message=flash_message,
                                          flash_error_message=flash_error_message,
                                          duration_options=duration_options)

@app.route('/admin/delete_secondary_user/<int:user_id>', methods=['POST'])
def delete_secondary_user_route(user_id):
    if not session.get('admin') or not session.get('is_primary_admin'):
        return redirect(url_for('login'))
    
    success, message = delete_admin_user(user_id)
    if success:
        session['flash_message'] = message
    else:
        session['flash_error_message'] = message
    return redirect(url_for('config_page'))


@app.route('/admin/logs/legend')
def log_legend():
    if 'admin' not in session:
        return redirect(url_for('login'))
    return render_template('log_legend.html')

@app.route('/admin/logs')
def view_logs():
    if 'admin' not in session:
        return redirect(url_for('login'))
 
    logs = get_audit_logs()
    return render_template('audit_logs.html', logs=logs)

def get_audit_logs(limit=100):
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?', (limit,))
    logs = c.fetchall()
    conn.close()
    
    formatted_logs = []
    for log_row in logs:
        log_dict = dict(log_row)
        if log_dict['old_value']:
            try: log_dict['old_value'] = json.loads(log_dict['old_value'])
            except json.JSONDecodeError: pass
        if log_dict['new_value']:
            try: log_dict['new_value'] = json.loads(log_dict['new_value'])
            except json.JSONDecodeError: pass
        formatted_logs.append(log_dict)
    return formatted_logs


@app.route('/debug')
def debug():
    if not session.get('admin') or not session.get('is_primary_admin'):
        return "Acesso negado.", 403
        
    all_settings = get_all_settings()
    settings_html = "<h2>Configurações Atuais:</h2><ul>"
    for k, v in all_settings.items():
        settings_html += f"<li><strong>{k}:</strong> {v}</li>"
    settings_html += "</ul>"

    return f"""
    Admin logado: {session.get('admin', False)}<br>
    Nome do admin: {session.get('admin_username', 'Não definido')}<br>
    Nível do admin: {session.get('admin_level', 'Não definido')}<br>
    É admin primário: {session.get('is_primary_admin', False)}<br>
    ADMIN_USER do config.py: {config.ADMIN_USER}<br>
    <hr>
    {settings_html}
    """

@app.route('/admin/exportar')
def exportar_consultas():
    if 'admin' not in session:
        return redirect(url_for('login'))
    
    admin_level = session.get('admin_level', 'primary')
    conn = sqlite3.connect('consultas.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    headers = []
    columns_to_fetch = []

    if admin_level == 'primary':
        c.execute('SELECT nome, email, matricula, telefone, data, horario FROM marcacoes ORDER BY data, horario')
        headers = ["Nome", "Email", "Matrícula", "Telefone", "Data", "Horário"]
        columns_to_fetch = ['nome', 'email', 'matricula', 'telefone', 'data', 'horario']
    else:
        c.execute('SELECT data, horario FROM marcacoes ORDER BY data, horario')
        headers = ["Data", "Horário"]
        columns_to_fetch = ['data', 'horario']

    consultas_data = c.fetchall()
    conn.close()

    wb = Workbook()
    ws = wb.active
    ws.title = "Consultas"
    ws.append(headers)

    for consulta_row in consultas_data:
        row_values = [consulta_row[col] for col in columns_to_fetch]
        ws.append(row_values)

    output = BytesIO()
    wb.save(output)
    output.seek(0)

    response = make_response(output.read())
    response.headers["Content-Disposition"] = "attachment; filename=consultas.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    log_audit(
        action="EXPORT_APPOINTMENTS", entity_type="System",
        new_value={
            "exported_records": len(consultas_data), 
            "export_by_user": session.get('admin_username'),
            "export_type": admin_level
            }
    )
    return response

if __name__ == '__main__':
    init_db()
    app.run(debug=True)