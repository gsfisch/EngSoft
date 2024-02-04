from flask import Flask, render_template, request, redirect, session, flash
from decouple import config
from json import dumps
import json
import uuid 
import hashlib
from pprint import pprint
import firebase_admin
from firebase_admin import auth, db, credentials
from pycpfcnpj import cpfcnpj


app = Flask(__name__,template_folder='view')
app.secret_key = 'secret'

firebaseConfig =  {
    'apiKey': config("FIREBASE_API_KEY"),
    'authDomain': config("FIREBASE_AUTH_DOMAIN"),
    'databaseURL':config("DATABASE_URL"),
    'projectId': config("FIREBASE_PROJECT_ID"),
    'storageBucket': config("FIREBASE_STORAGE_BUCKET"),
    'messagingSenderId': config("FIREBASE_MESSAGING_SENDER_ID"),
    'appId': config("FIREBASE_APP_ID"),
    'measurementId': config("FIREBASE_MEASUREMENT_ID"),
}

#initialize DB
dbCredentials = {
  "type": config("TYPE"),
  "project_id": config("FIREBASE_PROJECT_ID"),
  "private_key_id": config("PRIVATE_KEY_ID"),
  "private_key": config("PRIVATE_KEY"),
  "client_id": config("CLIENT_ID"),
  "auth_uri": config("AUTH_URI"),
  "token_uri": config("TOKEN_URI"),
  "auth_provider_x509_cert_url": config("AUTH_PROVIDER_CERT"),
  "client_x509_cert_url": config("CLIENT_CERT"),
  "universe_domain": config("UNIVERSE_DOMAIN"),
  "client_email": config("CLIENT_EMAIL") 
}
cred = credentials.Certificate(dbCredentials)
firebase_admin.initialize_app(cred , {"databaseURL": "https://pet-hub-rs-default-rtdb.firebaseio.com"})

# creating reference to root node
ref = db.reference("/")
users = db.reference("/users")

def get_stores():
    all_users = users.get()
    listOfStores = []
    if all_users is not None:
    # Itera sobre cada usuário
        for user_key, user_data in all_users.items():
            if 'onSaleProducts' in user_data:
                store = []
                store.append(user_key)
                store.append(user_data)
                listOfStores.append(store)
        return listOfStores


@app.route("/", methods =['POST', 'GET'])
def index():
    return render_template('index.html')

@app.route("/user", methods =['POST', 'GET'])
def user():
     if(session["userType"] == "pessoaJuridica"):
        return redirect("/minhaLoja")
     elif(session["userType"] == "pessoaFisica"):
        flash(session["user"], "user_name")
        return render_template("perfil.html")
   
    

def invalid_document_number(document_number):
    return not cpfcnpj.validate(document_number)

       

@app.route("/login", methods =['POST', 'GET'])
def login():

    if('user' in session):
      return redirect('/user')
    
    if request.method == 'POST':
        document_number = request.form.get('document')
        password = request.form.get('password')
        try:
            document_number_formatted = document_number.replace("-", "").replace(".", "").replace("/", "")
            if invalid_document_number(document_number_formatted):
                flash("número de documento inválido", "invalid_document_message")
                return render_template('login.html')
            elif len(password) < 7:
                flash("senha ou usuário inválidos", "invalid_user_password_message")
                return render_template('login.html')
            else:
                # busca no banco de dados o usuário pelo número do documento
                loginUser = users.child(document_number_formatted).get()

                # encodifica a senha do usuário
                password_encoded = password.encode('utf-8')
                sha1 = hashlib.sha1()
                # Update the hash object with the encoded password
                sha1.update(password_encoded)
                # Get the hexadecimal representation of the hash
                hashed_password = sha1.hexdigest()
            
                if loginUser["userPassword"] == hashed_password:
                    session["user"] = loginUser["userName"]
                    session["documentNumber"] = document_number_formatted
                    session["userType"] = "pessoaJuridica" if len(document_number_formatted) > 11 else "pessoaFisica"
                    if(session["userType"] == "pessoaJuridica"):
                        session["onSaleProducts"] = loginUser["onSaleProducts"]
                        return redirect("/minhaLoja")
                    elif(session["userType"] == "pessoaFisica"):
                        session["userCart"] = loginUser["userCart"]
                        session["userHistory"] = loginUser["userHistory"]
                        return redirect("/user")
                    # vai ter o login de administrador também
                else:
                    flash("senha ou usuário inválidos", "invalid_user_password_message")
                    return redirect("/login")
        except:
            flash("senha ou usuário inválidos", "invalid_user_password_message")
            return render_template('login.html')
    if request.method == "GET":
        return render_template('login.html')
        

def is_document_number_unique(document_number):
    try:
        query =  users.child(document_number).get()
    except:
        query = None

    return True if query == None else False
 
    
def invalid_password_or_document(password_encoded, password_confirmation_encoded, password_length, document_number):
    wrong_password = False
    unique_document = True
    is_invalid_document_number = False

    if  password_encoded != password_confirmation_encoded:
        flash("as senhas escolhidas divergem", "invalid_password_message")
        wrong_password = True
    elif password_length < 7:
        flash("senha inválida: a senha precisa ter no mínimo 6 caracteres", "invalid_password_message")
        wrong_password = True
    
    if invalid_document_number(document_number):
        flash("número de documento inválido", "invalid_document_message")
        is_invalid_document_number = True
    
    if not is_document_number_unique(document_number):
        flash("documento já cadastrado", "invalid_document_message")
        unique_document = False
        
    if  wrong_password or not unique_document or  is_invalid_document_number:
        return True
    

def cadastrarUsuario(tipoCadastro, password, password_confirmation, document_formatted,  name, email, uid):
    password_encoded = password.encode('utf-8')
    password_confirmation_encoded = password_confirmation.encode('utf-8')
    password_length = len(password)
    
    if invalid_password_or_document(password_encoded, password_confirmation_encoded, password_length, document_formatted):
        if(tipoCadastro == 'pessoaFisica'):
            return redirect('/cadastro')
        elif(tipoCadastro == 'pessoaJuridica'):
            return redirect('/cadastroLoja')
    else:
        # Create a SHA-1 hash object
        sha1 = hashlib.sha1()

        # Update the hash object with the encoded password
        sha1.update(password_encoded)

        # Get the hexadecimal representation of the hash
        hashed_password = sha1.hexdigest()

        if(tipoCadastro == "pessoaFisica"):
            products = {}
            userCart = {
                "products": products,
                "numberOfProducts": len(products), 
            }

            completedPurchases = {}
            userHistory = {
                "completedPurchases": len(completedPurchases)
            }
            users.child(document_formatted).set(
                {
                    "uid": uid,
                    "userName": name,
                    "userPassword": hashed_password,
                    "userEmail": email,
                    "userCart": userCart,
                    "userHistory": userHistory
                }
            )

        elif(tipoCadastro == 'pessoaJuridica'):
            products = {}
            onSaleProducts = {
                'products': products,
                'numberOfProducts': len(products), 
            }
            users.child(document_formatted).set(
                {
                    'uid': uid,
                    'userName': name,
                    'userPassword': hashed_password,
                    'userEmail': email,
                    'onSaleProducts': onSaleProducts
                }
            )        
    return redirect('/login')

@app.route("/cadastro", methods =['POST', 'GET'])
def cadastro():
    if request.method == 'POST':   
        idx = uuid.uuid4(),
        uid = str(idx) 
        email = request.form.get('email')
        name = request.form.get('nome')
        document = request.form.get('cpf')
        document_formatted = document.replace("-", "").replace(".", "").replace("/", "")
        password = request.form.get('password1')
        password_confirmation = request.form.get('password2')
        # TODO: teremos profile picture?
        # profilePicture = request.form.get('profilePicture')
        return cadastrarUsuario("pessoaFisica", password, password_confirmation, document_formatted, name, email, uid)
    else:
        return render_template('cadastro.html')


@app.route("/lojista")
def lojista():
    return render_template("/lojistaMenu.html")

@app.route("/minhaLoja")
def loja():
    if('user' in session):
        if(session["userType"] == "pessoaJuridica"):
            flash(session["user"], "user_name")
            return render_template("/minhaLoja.html")
        elif(session["userType"] == "pessoaFisica"):
             flash("Você não tem acesso a esta sessão logado como pessoa física.", "unauthorized_user_message_minhaLoja")
             return render_template("/lojistaMenu.html")
    else:
        return render_template("/login.html")

@app.route("/cadastroLoja", methods =['POST', 'GET'])
def cadastroLoja():

    if("user" in session):
        if(session["userType"] == "pessoaJuridica"):
            flash("Você não tem acesso a esta sessão já logado como pessoa jurídica.", "unauthorized_user_message_cadastroLoja")
            return render_template("/lojistaMenu.html")
        elif(session["userType"] == "pessoaFisica"):
             flash("Você não tem acesso a esta sessão logado como pessoa física.", "unauthorized_user_message_cadastroLoja")
             return render_template("/lojistaMenu.html")
     
    if request.method == 'POST':
        idx = uuid.uuid4(),
        uid = str(idx) 
        email = request.form.get('email')
        name = request.form.get('nome')
        document = request.form.get('cnpj')
        document_formatted = document.replace("-", "").replace(".", "").replace("/", "")
        password = request.form.get('password1')
        password_confirmation = request.form.get('password2')
        # TODO: teremos profile picture?
        # profilePicture = request.form.get('profilePicture')
        return cadastrarUsuario("pessoaJuridica", password, password_confirmation, document_formatted, name, email, uid)
    else:
        return render_template('cadastroLoja.html')

def checkUserPermissions(renderTemplate):
    if(session["userType"] == "pessoaJuridica"):
        flash("Você não tem acesso a esta sessão já logado como pessoa jurídica.", "unauthorized_user_message")
        return render_template(renderTemplate) 
    elif(session["userType"] == "pessoaFisica"):
        flash("Você não tem acesso a esta sessão logado como pessoa física.", "unauthorized_user_message")
        return render_template(renderTemplate) 


@app.route("/meuCarrinho", methods =['GET'])
def meuCarrinho():
    if(session["userCart"]["numberOfProducts"] == 0):
        flash("Carrinho vazio.", "empty_cart_message")
    return render_template("/meuCarrinho.html") 
        

@app.route("/meuHistorico", methods =['GET'])
def meuHistorico():
        if(session["userHistory"]["completedPurchases"] == 0):
            flash("Nenhuma compra efetuada.", "empty_history_message")
        return render_template("/meuHistorico.html")

@app.route("/meusProdutosEServicos", methods =['GET'])
def meusProdutosEservicos():
        if(session["onSaleProducts"]["numberOfProducts"] == 0):
            flash("Nenhum produto ou serviço cadastrados.", "empty_store_message")
        return render_template("/meusProdutosEServicos.html")

@app.route("/lojas")
def produto():
    if request.method == 'GET':
            if "user" not in session:
                return redirect("/")
            if (session["userType"] == "pessoaJuridica"):
                return redirect("/")
            else:
                stores = get_stores()
                return render_template("/lojas.html", stores_list=stores)
    
    
@app.route("/logout", methods =['GET'])
def logout():
    session.pop("user")
    return redirect("/")

@app.route("/excluirConta", methods =["GET"])
def deletarConta():
    try:
        users.child(session["documentNumber"]).delete()
        session.pop("user")
        return redirect("/")
    except:
         flash("Erro ao deletar conta.", "error_message_delete_account")
         if(session["userType"] == "pessoaJuridica"):
            return render_template("/minhaLoja.html")
         elif(session["userType"] == "pessoaFisica"):
            return render_template("/perfil.html")
    
@app.route("/navbar")
def navbar():
    return render_template("/navbar.html")


