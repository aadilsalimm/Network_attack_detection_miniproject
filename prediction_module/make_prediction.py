import pandas as pd
from joblib import load
import warnings
warnings.filterwarnings('ignore')

def load_model():
    return load("prediction_module/models/rfClassifier#3.joblib")

X_columns = [
    'flow_duration', 'Header_Length', 'Duration',
       'Srate', 'ack_count', 'syn_count', 'fin_count', 'urg_count', 'rst_count', 
        'TCP', 'UDP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',
       'Max', 'AVG', 'Std', 'Tot size', 'Number', 'Magnitue',
       'Radius', 'Covariance', 'Variance', 'Weight' 
]

def predict(model, input):
    return model.predict(input[X_columns])