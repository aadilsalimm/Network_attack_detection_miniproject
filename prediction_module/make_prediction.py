import pandas as pd
from joblib import load
import warnings
warnings.filterwarnings('ignore')

def load_model():
    return load("prediction_module/models/rfClassifier#temp.joblib")

X_columns = ['flow_duration','Duration','Srate','ack_count','syn_count',
                   'TCP','UDP','ICMP','Tot_sum','Min','Max','AVG','Std','Number','Magnitude','Weight']

def predict(model, input):
    result = {}
    predictions = model.predict(input[X_columns])
    ip_list = input['Source_IP'].to_list()
    timestamps = input['timestamp'].to_list()
    
    for ip,timestamp, prediction in zip(ip_list,timestamps, predictions):
        result[ip] = [timestamp,prediction]

    #print(f'debug info:\n{result}')
    return result