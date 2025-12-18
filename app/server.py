import os
from markupsafe import escape
from flask import Flask, request
app = Flask(__name__)

DATABASE_API_KEY = "SECRET_DEVSECOPS_TOKEN_12345"

@app.route('/')
def hello():
    user_input = request.args.get('name', 'Guest')
    return f"<h1>Hello, {user_input}!</h1>" 

if __name__ == '__main__':
    print(f"Using API Key: {DATABASE_API_KEY}")
    app.run(debug=True, host='0.0.0.0')
