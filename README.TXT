 Sistema de Marcação de Consultas

Este projeto é um sistema web desenvolvido com Flask e SQLite para gerenciar a marcação de consultas com uma psicóloga. Ele permite que funcionários agendem consultas dentro das regras estabelecidas e que o administrador gerencie os agendamentos.

## Funcionalidades
- Página de marcação de consultas.
- Restrição de uma consulta por semana por funcionário.
- Tela de confirmação antes do agendamento definitivo.
- Envio de e-mail de confirmação ao funcionário.
- Tela de administração para visualizar e excluir consultas.
- Sistema de login para o administrador.

## Tecnologias Utilizadas
- **Back-end:** Python 3, Flask
- **Banco de Dados:** SQLite
- **Front-end:** HTML, CSS
- **Serviço de E-mail:** smtplib (SMTP)

## Estrutura do Projeto
```
/
│── app.py                 # Código principal da aplicação
│── config.py              # Configurações do sistema (admin, email, SMTP)
│── consultas.db           # Banco de dados SQLite
│── templates/             # Templates HTML
│   ├── administracao.html
│   ├── confirmacao.html
│   ├── erro.html
│   ├── login.html
│   ├── marcacao.html
│   ├── sucesso.html
│── static/                # Arquivos estáticos (CSS, imagens)
│── README.md              # Documentação do projeto
```

## Instalação
1. **Clone o repositório:**
   ```sh
   git clone https://github.com/seu-usuario/seu-repositorio.git
   cd seu-repositorio
   ```

2. **Crie um ambiente virtual e instale as dependências:**
   
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   

3. **Configure o arquivo ''config.py''**
   - Defina o usuário e senha do administrador.
   - Configure os dados do servidor de e-mail SMTP.

4. **Inicialize o banco de dados:**
   
   python app.py
   

5. **Execute a aplicação:**
   
   flask run
   

## Uso
- Acesse `http://127.0.0.1:5000/` para marcar uma consulta.
- Para acessar o painel administrativo, vá até `http://127.0.0.1:5000/login` e faça login com as credenciais configuradas no `config.py`.

## Autor
- **Nome:** [Cayo Pereira]
- **Contato:** [cayopereira9.8@gmail.com]

---
Projeto desenvolvido para facilitar a marcação e administração de consultas com uma psicóloga.

