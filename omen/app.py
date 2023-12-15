from flask import Flask, render_template, redirect, request, make_response
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from werkzeug.security import check_password_hash

import sqlite3

import grpc
import os

import alert_pb2
import alert_pb2_grpc

GRPC_HOST = os.environ.get('GRPC_HOST')

app = Flask(__name__)

app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_TOKEN_LOCATION'] = ['cookies']

jwt = JWTManager(app)

@app.route('/')
def check_cookie():
    try:
        verify_jwt_in_request()
        return redirect('/alerts')
    except:
        return redirect('/login')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def poast_login():
    print("Login")
    username = request.form.get('username')
    password = request.form.get('password')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    
    conn.close()
    
    if user and (user[2] == password):
        access_token = create_access_token(identity=username)
        resp = make_response(redirect('/alerts'))
        set_access_cookies(resp, access_token)
        return resp, 200
    else:
        return redirect('/')

class Alert:
    name: str
    src_ip: str
    dst_ip: str

@app.route('/alerts')
@jwt_required( )
def alerts():
    res_alerts = []
    with grpc.insecure_channel(GRPC_HOST) as channel:
        stub = alert_pb2_grpc.AlertCapturerStub(channel)
        request = alert_pb2.Empty()
        
        try:
            alerts = stub.ReceiveAlert(request)
            for alert in alerts:
                print(alert)
                al = Alert()
                al.dst_ip = alert.d_ip
                al.src_ip = alert.src_ip
                al.name = alert.rule_name
                res_alerts.append(al)
        except grpc.RpcError as e:
            print(f"Error: gRPC request failed - {e}")
            
    return render_template('alerts.html', alerts=res_alerts)

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
