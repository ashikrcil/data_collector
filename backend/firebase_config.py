import firebase_admin
from firebase_admin import credentials, db

# Load the Firebase primary key (use raw string or double backslashes)
cred = credentials.Certificate(r"C:\DATA_TRACKER\rcil-data-bank-firebase-adminsdk-fbsvc-8a7d370454.json")

# Initialize Firebase with the database URL
firebase_admin.initialize_app(cred, {
    "databaseURL": "https://rcil-data-bank-default-rtdb.firebaseio.com/"
})
