from flask import Flask, request, jsonify, make_response
import time
app = Flask(__name__)

@app.route('/')
def index():
    return "<html><body><h1>Welcome to Honey Web</h1></body></html>"

@app.route('/login', methods=['POST'])
def login():
    # Honeypot: always return 401 Unauthorized but log attempt
    username = request.form.get('username','')
    password = request.form.get('password','')
    print(f"{time.ctime()} LOGIN_ATTEMPT {request.remote_addr} {username} {password}")
    resp = make_response("Unauthorized", 401)
    return resp

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
