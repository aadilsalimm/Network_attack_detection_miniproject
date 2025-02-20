from flask import Flask
from prediction_module.make_prediction import load_model, predict
from network_capture.capture import start_sniff


app = Flask(__name__)
model = load_model()

@app.route('/')
def home():
    input = start_sniff()
    prediction = predict(model, input)
    return str(prediction)



#app.debug = True
if __name__ == '__main__':
    app.run(debug=True)