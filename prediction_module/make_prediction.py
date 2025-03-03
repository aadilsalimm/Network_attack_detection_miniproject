import pandas as pd
from joblib import load
import warnings
warnings.filterwarnings('ignore')

def load_model():
    return load("prediction_module/models/rfClassifier#temp.joblib")

X_columns = ['flow_duration','Duration','Srate','ack_count','syn_count',
                   'TCP','UDP','ICMP','Tot_sum','Min','Max','AVG','Std','Number','Magnitude','Weight']

def predict(model, input):
    return model.predict(input[X_columns])