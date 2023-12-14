import firebase_admin
from firebase_admin import db, credentials


cred = credentials.Certificate("credentials.json")
firebase_admin.initialize_app(cred , {"databaseURL": "https://pet-hub-rs-default-rtdb.firebaseio.com"})

# creating reference to root node
ref = db.reference("/")

#check project name entry in the database
projectName = db.reference("/name").get()
print(projectName)
