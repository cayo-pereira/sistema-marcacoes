from waitress import serve
from app import app

if __name__ == '__main__':
    print("Iniciando servidor Waitress...")
    serve(app, host="127.0.0.1", port=5000, threads=4)
    input("Pressione Enter para encerrar...")


#serve(
 #   app,
  #  host="0.0.0.0",
   # port=5000,
    #url_scheme='https'  # Importante para trabalhar com HTTPS
#)


# Configurações SSL (substitua com seus caminhos reais)
    #CERT_FILE = "C:\cert.pem"
    #KEY_FILE = "C:\key.pem"
    
    #from waitress import serve
    
    # Modo desenvolvimento (sem SSL)
    # app.run(debug=True)
    
    # Modo produção com Waitress + SSL
    #serve(
       # app,
        #host="201.16.241.227",
       # port=8000,
       # url_scheme="https",
       # ssl_certificate=CERT_FILE,
       # ssl_private_key=KEY_FILE,
    #)