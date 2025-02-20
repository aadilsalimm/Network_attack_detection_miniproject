from flask import Flask, render_template
import threading
from flask_socketio import SocketIO
import webbrowser
from prediction_module.make_prediction import load_model, predict
from network_capture.capture import start_sniff


app = Flask(__name__)
socketio = SocketIO(app)
model = load_model()

attack_status = {"status": "No attack detected", "details": ""}

@app.route('/')
def home():
    return render_template("sample.html")


def packet_capture():
    global attack_status
    while True:
        input = start_sniff()
        predictions = predict(model, input)
        print(predictions)
        if 'DDos' or 'Dos' in predictions:
            attack_status["status"] = "Attack detected!!!"
            socketio.emit("attack_update",attack_status)
        

#app.debug = True
if __name__ == '__main__':
    threading.Thread(target=packet_capture, daemon=True).start()
    webbrowser.open("http://127.0.0.1:5000")
    socketio.run(app, debug=True)