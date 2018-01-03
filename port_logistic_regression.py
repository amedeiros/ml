import json
import csv
import pandas
import pprint
from sklearn.linear_model import LogisticRegression as Model

def train(features, target):
    model = Model()
    model.fit(features, target)
    return model

def predict(model, new_features):
    return model.predict(new_features)

def writePassRow(writer, protocol):
    writer.writerow({
        'protocol': protocol,
        'status': 1,
        'globalIP': 0,
    })

def writeFailRow(writer, protocol, globalIP=1):
    writer.writerow({
        'protocol': protocol,
        'status': 0,
        'globalIP': globalIP,
    })

def combineCidrs(ipPermission):
    cidrRange = ipPermission['ipRanges']

    for ipv4Range in ipPermission['ipv4Ranges']:
        cidrRange.append(ipv4Range['cidrIp'])

    for ipv6Range in ipPermission['ipv6Ranges']:
        cidrRange.append(ipv6Range['cidrIpv6'])
    
    return cidrRange

def convertIpProtocol(ipProtocol):
    protocol = 0 # Assume we do not know the protocol

    if ipProtocol == 'tcp':
        protocol = 1
    elif ipProtocol == 'udp':
        protocol = 2
    
    return protocol

def writeRanges(protocol, writer, cidrRange):
    for ipRange in cidrRange:
        if ipRange == '0.0.0.0/0':
            writeFailRow(writer, protocol)
        elif ipRange == '::/0':
            writeFailRow(writer, protocol, globalIP=2)
        else:
            writePassRow(writer, protocol)

def loadJsonAlerts(fileName='alerts.json'):
    alerts = []

    with open(fileName) as json_data:
        alerts = json.load(json_data)['alerts']
    
    return alerts

def split_train_and_test():
    """
    Split train and test data into an 80/20% split
    """
    data = pandas.read_csv('alerts.csv')

    data_train = data[:int(0.8*len(data))]
    data_test  = data[int(0.2*len(data)):]

    # Save them for further examination
    data_train.to_csv('train.csv')
    data_test.to_csv('test.csv')

    return data_train, data_test

def prepare():
    """
    Prepare reads in alert metadata as JSON and mines the data needed to train our model.
    Normalizing labels into integer representations.
    Status 1   = Pass
    Status 0   = Fail
    Protocol 0 = Unkown
    Protocol 1 = TCP
    Protocol 2 = UDP
    GlobalIP 0 = None
    GlobalIP 1 (IPV4) = 0.0.0.0/0
    GlobalIP 2 (IPV6) = ::/0
    """
    jsonAlerts = loadJsonAlerts()

    with open('alerts.csv', 'w') as alertsCsv:
        writer = csv.DictWriter(alertsCsv, fieldnames=['protocol', 'status', 'globalIP'])
        writer.writeheader()

        for alert in jsonAlerts:
            if 'securityGroup' not in alert['metadata']['data']: next

            for ipPermission in alert['metadata']['data']['securityGroup']['ipPermissions']:
                if ipPermission['fromPort'] is None or ipPermission['toPort'] is None: next

                protocol  = convertIpProtocol(ipPermission['ipProtocol'])
                cidrRange = combineCidrs(ipPermission)
                writeRanges(protocol, writer, cidrRange)

prepare()

data_train, data_test = split_train_and_test()

feature_test  = data_test.drop('status', axis=1)
feature_train = data_train.drop('status', axis=1)

model      = train(feature_train, data_train['status'])
prediction = predict(model, feature_test)

pprint.pprint(prediction)
pprint.pprint(model.score(feature_test, data_test['status']))
