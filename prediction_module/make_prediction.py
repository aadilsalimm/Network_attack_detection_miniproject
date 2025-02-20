import pandas as pd
from joblib import load
import warnings
warnings.filterwarnings('ignore')

def load_model():
    return load("prediction_module/models/rfClassifier#3.joblib")

def predict(model, input):
    return model.predict([input])