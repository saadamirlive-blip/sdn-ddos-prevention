# SDN-Based DDoS Prevention System

## Overview
This project implements an SDN-based security framework using Mininet and Ryu controller for dynamic segmentation and automated containment of DDoS attacks in enterprise networks.

## Features
- Enterprise network topology with 4 OpenFlow switches and 13 hosts
- ML-based anomaly detection using Random Forest
- Dynamic segmentation and traffic isolation
- Automated containment policies
- Comprehensive performance evaluation

## System Requirements
- Ubuntu 20.04 LTS or Kali Linux
- RAM: 16 GB minimum
- Storage: 50 GB free
- Python 3.8+

## Installation

### Step 1: Install Dependencies
```bash
sudo apt update
sudo apt install -y git python3 python3-pip mininet openvswitch-switch
sudo apt install -y hping3 iperf3 net-tools
```

### Step 2: Install Python Packages
```bash
pip3 install -r requirements.txt
```

### Step 3: Install Ryu Controller
```bash
sudo pip3 install ryu
```

### Step 4: Verify Installation
```bash
ryu-manager --version
mn --version
```

## Quick Start Guide

### 1. Train ML Model
```bash
cd controller
python3 train_model.py
```

### 2. Start Ryu Controller
```bash
ryu-manager --verbose enterprise_security_controller.py
```

### 3. Launch Network Topology (in new terminal)
```bash
cd topology
sudo python3 topology_enterprise.py
```

### 4. Run Attack Tests (in Mininet CLI)
```
mininet> h13 ping 10.0.3.1           # Test connectivity
mininet> h13 hping3 -S --flood -p 80 10.0.3.1  # SYN Flood
mininet> h13 hping3 --udp --flood -p 53 10.0.3.1  # UDP Flood
```

### 5. Monitor Performance
```bash
cd analysis
python3 performance_evaluation.py
```

## Project Files
- `controller/enterprise_security_controller.py` - Main Ryu controller
- `controller/train_model.py` - ML model training
- `topology/topology_enterprise.py` - Mininet topology
- `attacks/attack_scenarios.py` - Attack generation
- `analysis/performance_evaluation.py` - Results analysis

## Troubleshooting

### Common Issues:

1. **Controller Connection Failed**
   ```bash
   # Check if Ryu is running
   ps aux | grep ryu
   # Restart Ryu
   killall ryu-manager
   ryu-manager --verbose enterprise_security_controller.py
   ```

2. **Mininet Not Connecting**
   ```bash
   # Check OpenFlow
   sudo ovs-vsctl show
   # Reset switches
   sudo mn -c
   ```

3. **Permission Denied**
   ```bash
   sudo chmod +x *.py
   ```

4. **Module Not Found**
   ```bash
   pip3 install --upgrade ryu
   ```

## Performance Metrics
The system evaluates:
- Threat Containment Rate
- Response Time
- False Positive Rate
- Network Availability
- False Containment Rate

## Authors
[Your Name]
[Date]
