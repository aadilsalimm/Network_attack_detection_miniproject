from flask import Flask, render_template
import threading
from flask_socketio import SocketIO
import webview
import sys
import os
from prediction_module.make_prediction import load_model, predict
from network_capture.capture import start_sniff
from mitigation.mitigate import block_ip


app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
model = load_model()

attack_status = {"status": "No attack detected",
                 "total": 0, "benign": 0, "dos": 0, "ddos": 0}
server_started = False

@app.route('/')
def home():
    return render_template("home.html")


total_captured = 0
benign_count = 0
dos_count = 0
ddos_count = 0
def packet_capture():
    global attack_status
    global total_captured
    global benign_count
    global dos_count
    global ddos_count

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
        attack_status["ddos"] = ddos_count

        if any(value[1] == 'Dos' for value in predictions.values()):
            mal_ips = []
            for ip in predictions:
                if predictions[ip][1] == 'Dos':
                    mal_ips.append(ip)

            block_ip(mal_ips)

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

    sys.exit(0)
    