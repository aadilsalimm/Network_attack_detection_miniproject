from flask import Flask, render_template
import threading
from flask_socketio import SocketIO
import webview
import sys
from prediction_module.make_prediction import load_model, predict
from network_capture.capture import start_sniff


app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')
model = load_model()

attack_status = {"status": "No attack detected", "details": ""}
server_started = False

@app.route('/')
def home():
    return render_template("sample.html")


def packet_capture():
    global attack_status
    while True:
        input = start_sniff()
        predictions = list(predict(model, input))
        print(predictions)
        if predictions.count("Benign") < len(predictions)/2:
            attack_status["status"] = "Attack detected!!!"
            attack_status["details"] = f'Benign count : {predictions.count("Benign")}'
            socketio.emit("attack_update",attack_status)
        else:
            attack_status["status"] = "No attack detected"
            attack_status["details"] = ""
            socketio.emit("attack_update",attack_status)
        

def start_server():
    global server_started
    socketio.run(app, debug=False, use_reloader=False)
    server_started = True


if __name__ == '__main__':
    threading.Thread(target=start_server, daemon=True).start()
    threading.Thread(target=packet_capture, daemon=True).start()
    
    webview.create_window("Network monitor","http://127.0.0.1:5000", width=800, height=600)
    webview.start()

    sys.exit(0)
    