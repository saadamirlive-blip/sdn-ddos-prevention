#!/usr/bin/env bash
# =============================================================================
#  SDN Security Lab – Automated Environment Setup
#  Runs automatically inside GitHub Codespaces on container creation.
#  Safe to re-run manually: bash .devcontainer/install.sh
# =============================================================================
set -euo pipefail

VENV="/opt/sdn_venv"
LOG="/tmp/sdn_install.log"

log()  { echo -e "\033[1;34m[SETUP]\033[0m $*" | tee -a "$LOG"; }
ok()   { echo -e "\033[1;32m[  OK ]\033[0m $*" | tee -a "$LOG"; }
warn() { echo -e "\033[1;33m[ WARN]\033[0m $*" | tee -a "$LOG"; }

log "=== SDN Security Lab Environment Setup ==="
log "Timestamp: $(date)"

# ─── 1. System packages ───────────────────────────────────────────────────────
log "Installing system packages..."
if command -v apt-get &>/dev/null; then
    apt-get update -qq 2>>"$LOG"
    apt-get install -y -qq \
        git curl wget python3 python3-pip python3-venv python3-dev \
        openvswitch-switch openvswitch-testcontroller \
        mininet \
        hping3 iperf3 iperf \
        net-tools iproute2 iputils-ping tcpdump \
        bridge-utils \
        build-essential libssl-dev libffi-dev \
        graphviz \
        2>>"$LOG"
elif command -v apk &>/dev/null; then
    apk add --no-cache git curl wget python3 py3-pip python3-dev \
        openvswitch mininet hping3 iperf3 net-tools iproute2 tcpdump \
        build-base linux-headers libffi-dev openssl-dev 2>>"$LOG"
fi
ok "System packages installed"

# ─── 2. Start Open vSwitch ────────────────────────────────────────────────────
log "Starting Open vSwitch..."
service openvswitch-switch start 2>>"$LOG" || service openvswitch start 2>>"$LOG" || warn "OVS start failed"
ovs-vsctl show 2>>"$LOG" && ok "OVS running" || warn "OVS not ready yet"

# ─── 3. Python virtual environment ───────────────────────────────────────────
log "Creating Python virtual environment at $VENV ..."
python3 -m venv "$VENV" 2>>"$LOG" || python3 -m venv --system-site-packages "$VENV" 2>>"$LOG"
source "$VENV/bin/activate"

# ─── 4. Python dependencies ──────────────────────────────────────────────────
log "Installing Python packages..."

# Install compatible setuptools and pbr for Ryu setup hook
pip install "setuptools<65.0.0" "wheel" "pbr" "eventlet==0.30.2" -q 2>>"$LOG" || true
pip install --no-build-isolation "ryu" -q 2>>"$LOG" || pip install --no-build-isolation "git+https://github.com/osrg/ryu.git" -q 2>>"$LOG"

# ML & analysis stack
pip install scikit-learn pandas numpy matplotlib seaborn joblib networkx autopep8 ipykernel -q 2>>"$LOG"

ok "Python packages installed"

# ─── 5. Verify Ryu ───────────────────────────────────────────────────────────
log "Verifying Ryu..."
ryu-manager --version 2>>"$LOG" && ok "ryu-manager OK" || warn "ryu-manager check failed"

# ─── 6. Verify Mininet ───────────────────────────────────────────────────────
log "Verifying Mininet..."
mn --version 2>>"$LOG" && ok "Mininet OK" || warn "Mininet check failed"

# ─── 7. Train ML model ───────────────────────────────────────────────────────
log "Pre-training ML model..."
cd /workspaces/sdn-ddos-prevention/controller 2>/dev/null \
  || cd /workspaces/sdn_security_project/controller 2>/dev/null \
  || cd "$(find /workspaces -name 'train_model.py' -exec dirname {} \; 2>/dev/null | head -1)" \
  || { warn "Could not find controller directory – skipping model training"; exit 0; }

python3 train_model.py 2>>"$LOG" && ok "model.pkl + scaler.pkl generated" \
  || warn "Model training failed – run manually: cd controller && python3 train_model.py"

# ─── 8. Make scripts executable ──────────────────────────────────────────────
cd /workspaces/sdn-ddos-prevention 2>/dev/null || cd /workspaces/sdn_security_project 2>/dev/null || true
find . -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
ok "Script permissions set"

# ─── 9. Summary ──────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║        SDN Security Lab – Setup Complete ✅           ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Virtual env : $VENV                     ║"
echo "║  Log file    : $LOG                  ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Quick Start:                                        ║"
echo "║   Terminal 1: cd controller                          ║"
echo "║               ryu-manager enterprise_security_*.py  ║"
echo "║   Terminal 2: cd topology                            ║"
echo "║               sudo mn -c && sudo python3 topology_*  ║"
echo "╚══════════════════════════════════════════════════════╝"
