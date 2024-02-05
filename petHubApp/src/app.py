from flask import Flask, render_template, request, redirect, session, flash
from decouple import config
from json import dumps
import json
import uuid 
import hashlib
from pprint import pprint
import firebase_admin
from firebase_admin import auth, db, credentials, firestore
from pycpfcnpj import cpfcnpj
from datetime import datetime
import random


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


def getDate():
    data_atual = datetime.now()

    data_formatada = data_atual.strftime("%Y-%m-%d %H:%M:%S")

    return data_formatada

def getOrderID():
    date = getDate()

    numero_aleatorio_string = ''.join(random.choice('0123456789') for _ in range(6))

    orderId = date + "" + "-" + numero_aleatorio_string

    return orderId

def queryCompletedPurchases():
    completedPurchasesQuery = users.child(session['documentNumber']).child('userHistory').order_by_key().equal_to('completedPurchases').get()
    completedPurchases = 0

    if completedPurchasesQuery:
         for key, value in completedPurchasesQuery.items():
            completedPurchases = value

    return completedPurchases

def queryNumberOfProducts():
    numberOfProductsQuery = users.child(session['documentNumber']).child('userCart').order_by_key().equal_to('numberOfProducts').get()
    numberOfProducts = 0

    if numberOfProductsQuery:
        for key, value in numberOfProductsQuery.items():
            numberOfProducts = value

    return numberOfProducts

def clearCart():
    users.child(session['documentNumber']).child('userCart').child('products').delete()
    users.child(session['documentNumber']).child('userCart').update(
            {
                'numberOfProducts' : 0
            }
        )

def removeProductFromCart(product_key):

    users.child(session['documentNumber']).child('userCart').child('products').child(product_key).delete()

    numberOfProducts = queryNumberOfProducts()

    users.child(session['documentNumber']).child('userCart').update(
                {'numberOfProducts' : int(numberOfProducts) - 1})

def addProductToCart(productTitle, productPrice, productDescription):
    product = {
            'title': productTitle,
            'price': productPrice,
            'description': productDescription
        }

    productKey = productTitle

    while True:
        if users.child(session['documentNumber']).child('userCart').child('products').child(productKey).get() != None:
            productKey = productKey + "" + "'"
        else:
            break

    users.child(session['documentNumber']).child('userCart').child('products').child(productKey).set(
                {'description': productDescription, 
                 'title': productTitle, 
                 'price': productPrice, })
        
    numberOfProducts = queryNumberOfProducts()

    users.child(session['documentNumber']).child('userCart').update(
                {'numberOfProducts' : int(numberOfProducts) + 1})

def updateCart(totalValue, deliveryAdress, payment, date, orderId):

    users.child(session['documentNumber']).child('userHistory').child('orders').child(orderId).set(
            {
                'totalValue' : totalValue,
                'deliveryAdress' : deliveryAdress,
                'payment' : payment,
                'orderDate' : date
            }
        )

def updatePurchases(completedPurchases):
    users.child(session['documentNumber']).child('userHistory').update(
            {
                'completedPurchases' : int(completedPurchases) + 1
            }
        )

def getCartProducts():
    currentUser = users.get()
    listOfProducts = []
    totalValue = 0
    if currentUser is not None:
    # Itera sobre cada usuário
        for user_key, user_data in currentUser.items():
            # Verifica se o usuário tem o nó 'onSaleProducts'
            if 'userCart' in user_data:
                if user_data['userCart'] is not None:
                    on_sale_products = user_data['userCart']
                    if 'products' in on_sale_products:
                        products = on_sale_products['products']
                # Itera sobre cada produto em 'onSaleProducts'
                        for product_key, product_data in products.items():
                            # Verifica se o produto tem o campo 'nome'
                            if 'price' in product_data:
                                totalValue += float(product_data['price'])
                            product_complete = []
                            product_complete.append(product_key)
                            product_complete.append(product_data)
                            listOfProducts.append(product_complete)

    totalValueFormatted = "{:.{}f}".format(totalValue, 2)

    return listOfProducts, totalValueFormatted

def getUserHistory():
    currentUser = users.get()
    listOfOrders = []
    if currentUser is not None:
    # Itera sobre cada usuário
        for user_key, user_data in currentUser.items():
            # Verifica se o usuário tem o nó 'onSaleProducts'
            if 'userHistory' in user_data:
                if user_data['userHistory'] is not None:
                    doneOrders = user_data['userHistory']
                    if 'orders' in doneOrders:
                        orders = doneOrders['orders']
                # Itera sobre cada produto em 'onSaleProducts'
                        for order_key, order_data in orders.items():
                            # Verifica se o produto tem o campo 'nome'
                            listOfOrders.append(order_data)
    return listOfOrders                
    
# função para receber os nomes das lojas e fazer a requisição de produtos
def consultar_Lojas():
    currentUser = users.get()
    listOfProducts = []
    if currentUser is not None:
    # Itera sobre cada usuário
        for user_key, user_data in currentUser.items():
            # Verifica se o usuário tem o nó 'onSaleProducts'
            if 'onSaleProducts' in user_data:
                if user_data['onSaleProducts'] is not None:
                    on_sale_products = user_data['onSaleProducts']
                    if 'products' in on_sale_products:
                        products = on_sale_products['products']
                # Itera sobre cada produto em 'onSaleProducts'
                        for product_key, product_data in products.items():
                            # Verifica se o produto tem o campo 'nome'
                            listOfProducts.append(product_data)
        return listOfProducts

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

@app.route("/meuCarrinho", methods =['GET', 'POST'])
def meuCarrinho():
    if request.method == 'GET':
        numberOfProducts = queryNumberOfProducts()

        if(int(numberOfProducts) == 0):
            flash("Carrinho vazio.", "empty_cart_message")
            return render_template("/meuCarrinho.html", canBuy = False)
        else:
            listOfProducts, _ = getCartProducts()
            return render_template("/meuCarrinho.html", lista_de_itens=listOfProducts, canBuy = True) 
    
    elif request.method == 'POST':
        productKey = request.form.get('chaveProduto')
        productTitle = request.form.get('tituloProduto')

        removeProductFromCart(product_key=productKey)
        
        flash(f'Produto "{productTitle}" removido do carrinho com sucesso!', 'cart_updated_success')
        return redirect("/meuCarrinho")

@app.route("/meuHistorico", methods =['GET'])
def meuHistorico():
    completedPurchases = queryCompletedPurchases()

    if(int(completedPurchases) == 0):
        flash("Nenhuma compra efetuada.", "empty_history_message")
        return render_template("/meuHistorico.html")
    else:
        listOfOrders = getUserHistory()
        return render_template("/meuHistorico.html", lista_de_pedidos=listOfOrders) 
    
@app.route("/meusProdutosEServicos", methods =['GET'])
def meusProdutosEservicos():
        if(session["onSaleProducts"]["numberOfProducts"] == 0):
            flash("Nenhum produto ou serviço cadastrados.", "empty_store_message")
        return render_template("/meusProdutosEServicos.html")
    
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
         
@app.route("/produtos", methods = ['GET', 'POST'])
def produto():
    if request.method == 'GET':
            if "user" not in session:
                return redirect("/")
            if (session["userType"] == "pessoaJuridica"):
                return redirect("/")
            else:
                listaProdutos = consultar_Lojas()
                return render_template("/produtos.html", lista_de_itens=listaProdutos)
    elif request.method == 'POST':
        productTitle = request.form.get('tituloProduto')
        productPrice = request.form.get('precoProduto')
        productDescription = request.form.get('descricaoProduto')

        addProductToCart(productTitle=productTitle, productPrice=productPrice, productDescription=productDescription)

        flash(f'Produto "{productTitle}" adicionado ao carrinho com sucesso!', 'cart_updated_success')
        return redirect("/produtos")
    
@app.route("/processarFinalizarCompra", methods = ['POST'])
def processPurchase():
    return redirect('/finalizarCompra')

@app.route("/finalizarCompra", methods = ['GET', 'POST'])
def purchases():
    if request.method == 'GET':
        numberOfProducts = queryNumberOfProducts()

        if(int(numberOfProducts) == 0):
            flash("Carrinho vazio.", "empty_cart_message")
            return render_template("/finalizarCompra.html", canBuy = False)
        else:
            listOfProducts, totalValue = getCartProducts()
            return render_template("/finalizarCompra.html", lista_de_itens=listOfProducts, canBuy = True, totalValue = totalValue) 
    
    elif request.method == 'POST':
        productKey = request.form.get('chaveProduto')
        productTitle = request.form.get('tituloProduto')

        removeProductFromCart(product_key=productKey)
        
        flash(f'Produto "{productTitle}" removido do carrinho com sucesso!', 'cart_updated_success')
        return redirect("/finalizarCompra")

@app.route("/efetuarPedido", methods = ['POST'])
def purchaseDone():
        totalValue = request.form.get('valorTotal')
        deliveryAdress = request.form.get('endereco')
        payment = request.form.get('tipoPagamento')

        orderId=getOrderID()

        updateCart(totalValue=totalValue, deliveryAdress=deliveryAdress, payment=payment, date = getDate(), orderId=orderId)
        
        updatePurchases(completedPurchases = queryCompletedPurchases())

        clearCart()

        flash(f'Pedido "{orderId}" efetuado com sucesso!', 'order_success')
        return redirect("/meuHistorico")

@app.route("/navbar")
def navbar():
    return render_template("/navbar.html")


