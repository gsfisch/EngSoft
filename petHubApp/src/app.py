from flask import Flask, render_template, request, redirect, session
from decouple import config
import pyrebase
from json import dumps


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


firebase = pyrebase.initialize_app(firebaseConfig)
auth=firebase.auth()

@app.route("/", methods =['POST', 'GET'])
def index():
    return render_template('index.html')

@app.route("/login", methods =['POST', 'GET'])
def login():

    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            print(user)
            session['user'] = email
        except:
            return 'Failed to login'
        
    return render_template('login.html')

@app.route("/cadastro", methods =['POST', 'GET'])
def cadastro():
    if request.method == 'POST':
        # Obtenha os dados do formulário
        email = request.form.get('email')
        password = request.form.get('password')
        display_name = request.form.get('display_name')

        try:
            # Crie um novo usuário no Firebase Authentication
            # user = auth.create_user(
            #     email=email,
            #     password=password,
            #     display_name=display_name
            # )

            # Realize ações adicionais conforme necessário

            return dumps(user)

        except Exception as e:
            return dumps(str(e))

    return render_template('cadastro.html')



