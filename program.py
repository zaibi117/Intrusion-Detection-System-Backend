import sys
from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from threading import Thread, Event
import numpy as np
import pandas as pd
import json
import ipaddress
from urllib.request import urlopen
import joblib
import os
import warnings
import logging
from tensorflow import keras
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

warnings.filterwarnings("ignore")
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

app = Flask(__name__)
CORS(app)

flow_count = 0
flow_df = pd.DataFrame(columns=[
    'FlowID', 'FlowDuration', 'BwdPacketLenMax', 'BwdPacketLenMin', 'BwdPacketLenMean', 
    'BwdPacketLenStd', 'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 
    'FwdIATTotal', 'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin', 
    'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax', 'BwdIATMin', 
    'FwdPSHFlags', 'FwdPackets_s', 'MaxPacketLen', 'PacketLenMean', 
    'PacketLenStd', 'PacketLenVar', 'FINFlagCount', 'SYNFlagCount', 
    'PSHFlagCount', 'ACKFlagCount', 'URGFlagCount', 'AvgPacketSize', 
    'AvgBwdSegmentSize', 'InitWinBytesFwd', 'InitWinBytesBwd', 
    'ActiveMin', 'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin', 
    'Src', 'SrcPort', 'Dest', 'DestPort', 'Protocol', 
    'FlowStartTime', 'FlowLastSeen', 'PName', 'PID', 
    'Classification', 'Probability', 'Risk'
])

ae_features = np.array([
    'FlowDuration', 'BwdPacketLengthMax', 'BwdPacketLengthMin', 'BwdPacketLengthMean',
    'BwdPacketLengthStd', 'FlowIATMean', 'FlowIATStd', 'FlowIATMax', 'FlowIATMin',
    'FwdIATTotal', 'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin',
    'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax', 'BwdIATMin',
    'FwdPSHFlags', 'FwdPackets/s', 'PacketLengthMax', 'PacketLengthMean',
    'PacketLengthStd', 'PacketLengthVariance', 'FINFlagCount', 'SYNFlagCount',
    'PSHFlagCount', 'ACKFlagCount', 'URGFlagCount', 'AveragePacketSize',
    'BwdSegmentSizeAvg', 'FWDInitWinBytes', 'BwdInitWinBytes', 'ActiveMin',
    'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin'
])

src_ip_dict = {}
current_flows = {}
FlowTimeout = 600
thread_stop_event = Event()
classifier = None

try:
    imputer = joblib.load('models/imputer.pkl')
    scaler = joblib.load('models/scaler.pkl')
    classifier = joblib.load('models/model.pkl')
    encoder = joblib.load('models/encoder.pkl')
except Exception as e:
    logging.error(f"Error loading models: {e}")
    
def classify(features):
    global flow_count, flow_df, src_ip_dict
    
    if len(features) < 40:
        return None
    
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    
    try:
        features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
        
        if len(feature_string) > 0:
            src_ip = feature_string[0]
            if src_ip in src_ip_dict:
                src_ip_dict[src_ip] += 1
            else:
                src_ip_dict[src_ip] = 1
        
        if all(np.isnan(x) for x in features):
            return None
        
        features_array = np.array(features).reshape(1, -1)
        features_array = imputer.transform(features_array)
        features_array = scaler.transform(features_array)

        if classifier is None:
            return None
            
        result = classifier.predict(features_array)
        proba = classifier.predict_proba(features_array)
        
        try:
            if hasattr(encoder, 'classes_') and not isinstance(result[0], str):
                result = encoder.inverse_transform(result)
        except Exception:
            pass
            
        proba_score = [float(proba[0].max())]
        proba_risk = float(sum(proba[0, 1:]) if proba.shape[1] > 1 else 0)
        
    except Exception:
        return None
    
    if proba_risk > 0.8:
        risk = ["Very High"]
    elif proba_risk > 0.6:
        risk = ["High"]
    elif proba_risk > 0.4:
        risk = ["Medium"]
    elif proba_risk > 0.2:
        risk = ["Low"]
    else:
        risk = ["Minimal"]
    
    if isinstance(result, np.ndarray):
        classification = [str(result[0])]
    else:
        classification = [str(result)]
    
    flow_count += 1
    
    try:
        flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk
    except ValueError:
        expected_cols = len(flow_df.columns)
        current_vals = 1 + len(record) + 1 + 1 + 1
        if current_vals < expected_cols:
            padding = [None] * (expected_cols - current_vals)
            flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk + padding
    
    return {
        'flow_id': flow_count,
        'record': record,
        'classification': classification[0],
        'probability': float(proba_score[0]),
        'risk': risk[0],
        'label': classification[0]
    }

def process_packet(p):
    try:
        if p is None or not hasattr(p, 'haslayer') or not p.haslayer(IP):
            return None
            
        packet = PacketInfo()
        
        try:
            packet.setDest(p)
            packet.setSrc(p)
            packet.setProtocol(p)
            packet.setTimestamp(p)
            packet.setPayloadBytes(p)
            packet.setHeaderBytes(p)
            packet.setPacketSize(p)
        except AttributeError:
            return None
        
        if p.haslayer(TCP):
            packet.setSrcPort(p)
            packet.setDestPort(p)
            packet.setPSHFlag(p)
            packet.setFINFlag(p)
            packet.setSYNFlag(p)
            packet.setACKFlag(p)
            packet.setURGFlag(p)
            packet.setRSTFlag(p)
            packet.setWinBytes(p)
        elif p.haslayer(UDP):
            packet.setSrcPort(p)
            packet.setDestPort(p)
            packet.setPSHFlag(None)
            packet.setFINFlag(None)
            packet.setSYNFlag(None)
            packet.setACKFlag(None)
            packet.setURGFlag(None)
            packet.setRSTFlag(None)
            packet.setWinBytes(None)
        else:
            packet.setSrcPort(None)
            packet.setDestPort(None)
            packet.setPSHFlag(None)
            packet.setFINFlag(None)
            packet.setSYNFlag(None)
            packet.setACKFlag(None)
            packet.setURGFlag(None)
            packet.setRSTFlag(None)
            packet.setWinBytes(None)
            
        try:
            packet.setFwdID()
            packet.setBwdID()
        except (AttributeError, TypeError):
            return None

        if packet.getFwdID() in current_flows:
            flow = current_flows[packet.getFwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                result = classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
                return result

            elif (p.haslayer(TCP) and (packet.getFINFlag() or packet.getRSTFlag())):
                flow.new(packet, 'fwd')
                result = classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                return result
            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow
                return None

        elif packet.getBwdID() in current_flows:
            flow = current_flows[packet.getBwdID()]

            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                result = classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
                return result

            elif (p.haslayer(TCP) and (packet.getFINFlag() or packet.getRSTFlag())):
                flow.new(packet, 'bwd')
                result = classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                return result
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
                return None
        else:
            try:
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
                return None
            except Exception:
                return None

    except Exception:
        return None

def sniff_and_detect():
    global thread_stop_event
    
    def packet_callback(p):
        result = process_packet(p)
        if result:
            logging.info(f"Classified flow: {result['flow_id']} as {result['classification']}")
            
    while not thread_stop_event.isSet():
        try:
            sniff(prn=packet_callback, store=False, timeout=5)
        except Exception:
            break

    for f in current_flows.values():
        classify(f.terminated())

@app.route('/api', methods=['GET'])
def api_index():
    return jsonify({'status': 'online'})

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify({
        'status': 'online',
        'flows_processed': flow_count,
        'active_flows': len(current_flows)
    })

@app.route('/api/start', methods=['POST'])
def api_start_sniffing():
    global thread_stop_event
    
    if not thread_stop_event.is_set():
        thread_stop_event.clear()
        thread = Thread(target=sniff_and_detect)
        thread.start()
        return jsonify({'status': 'started', 'message': 'Packet sniffing started'})
    else:
        return jsonify({'status': 'already_running', 'message': 'Packet sniffing is already running'})

@app.route('/api/stop', methods=['POST'])
def api_stop_sniffing():
    global thread_stop_event
    
    if not thread_stop_event.is_set():
        thread_stop_event.set()
        return jsonify({'status': 'stopped', 'message': 'Packet sniffing stopped'})
    else:
        return jsonify({'status': 'not_running', 'message': 'Packet sniffing is not running'})

@app.route('/api/flows', methods=['GET'])
def api_get_flows():
    flows = flow_df.to_dict(orient='records')
    return jsonify({'flows': flows, 'count': len(flows)})

@app.route('/api/ip-stats', methods=['GET'])
def api_get_ip_stats():
    ip_data = {'ip_addresses': [], 'counts': []}
    
    for ip, count in src_ip_dict.items():
        ip_data['ip_addresses'].append(ip)
        ip_data['counts'].append(count)
    
    return jsonify(ip_data)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)