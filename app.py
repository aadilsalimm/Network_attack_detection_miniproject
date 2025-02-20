from flask import Flask
from prediction_module.make_prediction import load_model, predict


app = Flask(__name__)
model = load_model()

@app.route('/')
def home():
    input = [0.0,0.0,64.0,39.92749980961083,0.0,0.0,0.0,0.0,0.0,0.0,0.0,1.0,1.0,1.0,441.0,42.0,42.0,42.0,0.0,42.0,9.5,9.16515138991168,0.0,0.0,0.0,141.55]
    prediction = predict(model, input)
    return str(prediction)



#app.debug = True
if __name__ == '__main__':
    app.run(debug=True)