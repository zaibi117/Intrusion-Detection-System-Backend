# Intrusion Detection System (IDS) - Flask Backend

## Overview

This project is a Flask-based backend for an Intrusion Detection System (IDS) that analyzes network packets in real-time, classifies them based on machine learning models, and provides RESTful API endpoints for managing packet sniffing, monitoring flow statistics, and retrieving results.

The backend uses Scapy for packet analysis, TensorFlow for classification, and other libraries like scikit-learn and pandas for preprocessing and model handling. The system is designed to classify network traffic and assess its risk level, offering API endpoints to start, stop, and monitor sniffing processes.

## Requirements

To set up the environment for running the IDS Flask backend, please follow these steps:

1. **Create a Python 3.10 Virtual Environment**
   ```bash
   python3.10 -m venv venv
   ```

2. **Activate the Virtual Environment**
   - On Windows:
     ```bash
     venv\Scripts\activate
     ```
   - On macOS/Linux:
     ```bash
     source venv/bin/activate
     ```

3. **Install Required Dependencies**
   After activating the virtual environment, install the dependencies from the `requirements.txt` file:
   ```bash
   pip install -r requirements.txt
   ```

## Project Setup

### File Structure

- `app.py` - The main Flask application containing all the routes and logic.
- `models/` - Directory containing the trained models (`imputer.pkl`, `scaler.pkl`, `model.pkl`, `encoder.pkl`).
- `flow/` - Contains classes `Flow` and `PacketInfo` used for network flow and packet analysis.
- `requirements.txt` - A list of dependencies for the project.

### Key Features

1. **Packet Sniffing**: Real-time sniffing and analysis of network packets using Scapy.
2. **Flow Classification**: Classifies network traffic into different types (normal or malicious) based on trained models.
3. **Risk Assessment**: Assigns a risk level (Minimal, Low, Medium, High, Very High) to the network traffic based on classification probability.
4. **REST API**:
   - `/api/status`: Get the current status of the IDS and the number of processed flows.
   - `/api/start`: Start packet sniffing and flow analysis.
   - `/api/stop`: Stop the sniffing process.
   - `/api/flows`: Retrieve the list of processed flows with detailed classification and risk levels.
   - `/api/ip-stats`: Get statistics on IP addresses involved in the flows.

### Running the Application

1. **Start the Flask Application**
   After setting up the environment and installing dependencies, you can start the Flask application using:
   ```bash
   python app.py
   ```

2. **Access the API Endpoints**
   Once the server is running, you can access the following endpoints:
   - `GET /api`: Basic health check, confirms if the server is online.
   - `GET /api/status`: Check the status of the IDS (e.g., number of processed flows, active flows).
   - `POST /api/start`: Start sniffing network packets.
   - `POST /api/stop`: Stop sniffing network packets.
   - `GET /api/flows`: Retrieve the details of classified flows.
   - `GET /api/ip-stats`: Retrieve the statistics of source IPs involved in network flows.

### API Responses

- **GET /api/status**
  ```json
  {
    "status": "online",
    "flows_processed": 10,
    "active_flows": 5
  }
  ```

- **GET /api/flows**
  ```json
  {
    "flows": [
      {
        "flow_id": 1,
        "record": [...],
        "classification": "Normal",
        "probability": 0.98,
        "risk": "Low",
        "label": "Normal"
      },
      ...
    ],
    "count": 10
  }
  ```

- **GET /api/ip-stats**
  ```json
  {
    "ip_addresses": ["192.168.1.1", "192.168.1.2", ...],
    "counts": [5, 3, ...]
  }
  ```

### Model Requirements

The backend expects the following trained models to be present in the `models/` directory:
- `imputer.pkl`: Model for imputing missing values.
- `scaler.pkl`: Scaler for normalizing the features.
- `model.pkl`: Trained classification model.
- `encoder.pkl`: Label encoder for converting predictions back to categorical values.

### Logging

The backend uses the `python-json-logger` package to log activities in JSON format. Logs include classified flows and any errors encountered during packet processing.

---

For any issues or feature requests, feel free to create an issue in the repository or contact the developer team.