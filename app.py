from flask import Flask, render_template, request, redirect
import threading
from flask_socketio import SocketIO
import webview
import sys
import os
from prediction_module.make_prediction import load_model, predict
from network_capture.capture import start_sniff
from mitigation.mitigate import block_ip, unblock_ip
from database.db_ops import db_connect, add_data, close_db_connection, get_log, del_data


app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
model = load_model()
db_connect()


attack_status = {"status": "No attack detected",
                 "total": 0, "benign": 0, "dos": 0,}
server_started = False

@app.route('/')
def home():
    return render_template("home.html",attack_status=attack_status)


@app.route('/log')
def log_page():
    log = get_log()
    return render_template("log_page.html", log=log)


@app.route('/delete-record', methods=['POST'])
def delete_record():
    ip = request.form.get('ip')
    unblock_ip(ip)
    del_data(ip)

    return  redirect('/log')


total_captured = 0
benign_count = 0
dos_count = 0

def packet_capture():
    global attack_status
    global total_captured
    global benign_count
    global dos_count

    while True:
        input = start_sniff()
        predictions = predict(model, input)
        print(f'debug info:\n{predictions}')
        
        total_captured += len(predictions.values())
        dos_count += sum(1 for value in predictions.values() if value[1] == 'Dos')
        benign_count += sum(1 for value in predictions.values() if value[1] == 'Normal')

        print(f'total: {total_captured}\ndos: {dos_count}\nbenign: {benign_count}')

        attack_status["total"] = total_captured
        attack_status["benign"] = benign_count
        attack_status["dos"] = dos_count

        if any(value[1] == 'Dos' for value in predictions.values()):
            mal_ips = []
            timestamps = []
            for ip in predictions:
                if predictions[ip][1] == 'Dos':
                    mal_ips.append(ip)
                    timestamps.append(predictions[ip][0])

            block_ip(mal_ips)
            add_data(mal_ips=mal_ips, timestamps=timestamps)

            attack_status["status"] = f"Attack detected at {mal_ips}"
            socketio.emit("attack_update",attack_status)
        else:
            attack_status["status"] = "No attack detected"
            socketio.emit("attack_update",attack_status)       
        

def start_server():
    global server_started
    #Uncomment below line for linux
    os.environ["WEBKIT_DISABLE_COMPOSITING_MODE"] = "1"
    socketio.run(app, debug=False, use_reloader=False)
    socketio.emit("attack_update", attack_status)


if __name__ == '__main__':
    server_started = True
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=packet_capture, daemon=True).start()
    
    webview.create_window("Network monitor","http://127.0.0.1:5000", width=800, height=600)
    webview.start()

    close_db_connection()
    sys.exit(0)