#!/usr/bin/env bash
# =============================================================================
#  SDN Security Lab – One-Click Environment Setup Script
# =============================================================================

VENV="/opt/sdn_venv"
LOG="/tmp/sdn_install.log"

echo "=== SDN Security Lab Setup Starting ===" | tee -a "$LOG"

# 1. System Packages
echo "Installing system dependencies..." | tee -a "$LOG"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq || true
sudo apt-get install -y -qq \
    git curl wget python3 python3-pip python3-venv python3-dev \
    openvswitch-switch openvswitch-testcontroller \
    mininet \
    hping3 iperf3 iperf \
    net-tools iproute2 iputils-ping tcpdump \
    bridge-utils \
    build-essential libssl-dev libffi-dev \
    graphviz || true

# 2. Start Open vSwitch
echo "Starting Open vSwitch..." | tee -a "$LOG"
sudo service openvswitch-switch start || true

# 3. Python Virtual Environment
echo "Setting up Python virtual environment..." | tee -a "$LOG"
sudo python3 -m venv "$VENV" || true
sudo chown -R $(whoami) "$VENV" 2>/dev/null || true
source "$VENV/bin/activate" || true

# 4. Install Python Packages
echo "Installing Python requirements..." | tee -a "$LOG"
pip install --upgrade pip "setuptools<65.0.0" wheel pbr "eventlet==0.30.2" -q || true
pip install --no-build-isolation "ryu" -q || pip install --no-build-isolation "git+https://github.com/osrg/ryu.git" -q || true
pip install scikit-learn pandas numpy matplotlib seaborn joblib networkx autopep8 ipykernel -q || true

# 5. Pre-train ML Model
echo "Pre-training ML model..." | tee -a "$LOG"
cd controller 2>/dev/null || cd /workspaces/sdn-ddos-prevention/controller 2>/dev/null || true
python3 train_model.py || true

# 6. Add default alias for venv activation
echo "source /opt/sdn_venv/bin/activate 2>/dev/null || true" >> ~/.bashrc

echo "=== Setup Completed Successfully ✅ ===" | tee -a "$LOG"
echo "To start controller: source /opt/sdn_venv/bin/activate && cd controller && ryu-manager --verbose enterprise_security_controller.py"
