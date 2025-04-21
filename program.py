from flask import Flask, request, jsonify
from flask_cors import CORS
from scapy.sendrecv import sniff
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

# Import custom flow analysis modules
from flow.Flow import Flow
from flow.PacketInfo import PacketInfo

# Suppress warnings
warnings.filterwarnings("ignore")

# Configure GPU usage
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_ip_country(addr=''):
    """Get country information for an IP address"""
    try:
        if addr == '':
            url = 'https://ipinfo.io/json'
        else:
            url = 'https://ipinfo.io/' + addr + '/json'
        res = urlopen(url)
        data = json.load(res)
        return data['country']
    except Exception:
        return None

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Setup data storage
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

# Features for the autoencoder
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

# Global variables
src_ip_dict = {}
current_flows = {}
FlowTimeout = 600
thread_stop_event = Event()
classifier = None

# Load models
try:
    logger.info("Loading models...")
    normalisation = joblib.load('models/imputer.pkl')
    classifier = joblib.load('models/model.pkl')
    predict_fn_rf = lambda x: classifier.predict_proba(x).astype(float)
    logger.info("Models loaded successfully")
except Exception as e:
    logger.error(f"Error loading models: {e}")

def classify(features):
    """Classify network flow based on features"""
    global flow_count, flow_df, src_ip_dict
    
    # Handle feature processing
    feature_string = [str(i) for i in features[39:]]
    record = features.copy()
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features[:39]]
    
    # Track source IP statistics
    if feature_string[0] in src_ip_dict:
        src_ip_dict[feature_string[0]] += 1
    else:
        src_ip_dict[feature_string[0]] = 1
    
    # Handle missing values
    if np.nan in features:
        return None
    
    # Classify the flow
    result = classifier.predict([features])
    proba = predict_fn_rf([features])
    proba_score = [proba[0].max()]
    proba_risk = sum(list(proba[0, 1:]))
    
    # Determine risk level
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
    
    classification = [str(result[0])]
    if result != 'Benign':
        logger.info(f"Detected non-benign flow: {feature_string + classification + proba_score}")
    
    # Increment flow counter
    flow_count += 1
    
    # Store flow in dataframe
    flow_df.loc[len(flow_df)] = [flow_count] + record + classification + proba_score + risk
    
    return {
        'flow_id': flow_count,
        'record': record,
        'classification': classification[0],
        'probability': proba_score[0],
        'risk': risk[0],
        'label': result
    }

def process_packet(p):
    """Process a captured network packet"""
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        # Handle forward flow
        if packet.getFwdID() in current_flows:
            flow = current_flows[packet.getFwdID()]

            # Check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                result = classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
                return result

            # Check for FIN flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                result = classify(flow.terminated())
                del current_flows[packet.getFwdID()]
                return result
            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow
                return None

        # Handle backward flow
        elif packet.getBwdID() in current_flows:
            flow = current_flows[packet.getBwdID()]

            # Check for timeout
            if (packet.getTimestamp() - flow.getFlowLastSeen()) > FlowTimeout:
                result = classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow
                return result

            # Check for FIN flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                result = classify(flow.terminated())
                del current_flows[packet.getBwdID()]
                return result
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
                return None
        else:
            # New flow
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow
            return None

    except AttributeError:
        # Not IP or TCP
        return None
    except Exception as e:
        logger.error(f"Error processing packet: {e}")
        return None

def sniff_and_detect():
    """Function to sniff packets and detect anomalies"""
    global thread_stop_event
    
    logger.info("Begin network sniffing")
    
    # Function to process each packet
    def packet_callback(p):
        result = process_packet(p)
        if result:
            # Log classification results
            logger.info(f"Classified flow: {result['flow_id']} as {result['classification']}")
            logger.info(f"Flow risk: {result['risk']}")
            
    while not thread_stop_event.isSet():
        try:
            # Start packet sniffing
            sniff(prn=packet_callback, store=False, timeout=5)
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            break

    # Process any remaining flows
    for f in current_flows.values():
        classify(f.terminated())

# API Routes
@app.route('/api', methods=['GET'])
def api_index():
    """API endpoint to check if the service is running"""
    return jsonify({'status': 'online'})

@app.route('/api/status', methods=['GET'])
def api_status():
    """API endpoint to check if the service is running"""
    return jsonify({
        'status': 'online',
        'flows_processed': flow_count,
        'active_flows': len(current_flows)
    })

@app.route('/api/start', methods=['POST'])
def api_start_sniffing():
    """API endpoint to start packet sniffing"""
    global thread_stop_event
    
    # Check if already running
    if not thread_stop_event.is_set():
        logger.info("Starting packet sniffing")
        thread_stop_event.clear()
        thread = Thread(target=sniff_and_detect)
        thread.start()
        return jsonify({'status': 'started', 'message': 'Packet sniffing started'})
    else:
        logger.info("Already sniffing")
        return jsonify({'status': 'already_running', 'message': 'Packet sniffing is already running'})

@app.route('/api/stop', methods=['POST'])
def api_stop_sniffing():
    """API endpoint to stop packet sniffing"""
    global thread_stop_event
    
    if not thread_stop_event.is_set():
        thread_stop_event.set()
        return jsonify({'status': 'stopped', 'message': 'Packet sniffing stopped'})
    else:
        return jsonify({'status': 'not_running', 'message': 'Packet sniffing is not running'})

@app.route('/api/flows', methods=['GET'])
def api_get_flows():
    """API endpoint to get all processed flows"""
    # Convert dataframe to dictionary format
    flows = flow_df.to_dict(orient='records')
    return jsonify({'flows': flows, 'count': len(flows)})

@app.route('/api/ip-stats', methods=['GET'])
def api_get_ip_stats():
    """API endpoint to get statistics about source IPs"""
    ip_data = {'ip_addresses': [], 'counts': []}
    
    for ip, count in src_ip_dict.items():
        ip_data['ip_addresses'].append(ip)
        ip_data['counts'].append(count)
    
    return jsonify(ip_data)

if __name__ == '__main__':
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)