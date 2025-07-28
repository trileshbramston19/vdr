from app import db, bcrypt, User
from flask import Flask

app = Flask(__name__)
app.app_context().push()  # Push context for db.session to work

email = 'admin@vdr.com'
password = '1234'  # Plain password
hashed = bcrypt.generate_password_hash(password).decode('utf-8')

user = User(email=email, password=hashed)
db.session.add(user)
db.session.commit()
print("✅ User created.")
