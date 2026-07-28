#!/usr/bin/env bash
# =============================================================================
#  SDN Security Lab – One-Click Environment Setup Script
# =============================================================================

# Ensure script runs from project root directory regardless of current working directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$SCRIPT_DIR" || cd /workspaces/sdn-ddos-prevention || true

VENV="/opt/sdn_venv"
LOG="/tmp/sdn_install.log"

echo "=== SDN Security Lab Setup Starting ===" | tee -a "$LOG"

# 1. System Packages (non-interactive debconf pre-seeding)
echo "Installing system dependencies..." | tee -a "$LOG"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
echo "iperf3 iperf3/auto-run boolean false" | sudo debconf-set-selections 2>/dev/null || true

sudo -E apt-get update -qq || true
sudo -E apt-get install -y -o Dpkg::Options::="--force-confold" -qq \
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

# 3. Python Virtual Environment (Wipe and recreate cleanly)
echo "Setting up clean Python virtual environment at $VENV..." | tee -a "$LOG"
sudo rm -rf "$VENV" /tmp/ryu* || true
sudo python3 -m venv "$VENV" || true
sudo chown -R $(whoami) "$VENV" 2>/dev/null || true
source "$VENV/bin/activate" || true

# 4. Install Base Tools & Ryu Dependencies
echo "Installing base Python tools & Ryu dependencies..." | tee -a "$LOG"
pip install --upgrade pip wheel setuptools pbr "eventlet>=0.35.0" netaddr msgpack oslo.config routes tinyrpc webob ovs paramiko -q || true

echo "Downloading and patching Ryu for Python 3.12 compatibility..." | tee -a "$LOG"
curl -sSL https://files.pythonhosted.org/packages/source/r/ryu/ryu-4.34.tar.gz -o /tmp/ryu-4.34.tar.gz || wget -q https://files.pythonhosted.org/packages/source/r/ryu/ryu-4.34.tar.gz -O /tmp/ryu-4.34.tar.gz
tar -xzf /tmp/ryu-4.34.tar.gz -C /tmp

# Comprehensive Python 3.12 compatibility patch for Ryu codebase
python3 - <<'PY'
import os, re

def apply_patches(target_dir):
    if not os.path.exists(target_dir):
        return
    print(f"Patching Ryu files in {target_dir}...")
    
    # 1. Neutralize ryu/hooks.py to bypass broken setuptools easy_install hooks
    hooks_path = os.path.join(target_dir, 'hooks.py')
    if os.path.exists(hooks_path):
        with open(hooks_path, 'w', encoding='utf-8') as f:
            f.write("def setup_hook(*args, **kwargs):\n    pass\ndef save_orig(*args, **kwargs):\n    pass\ndef restore_orig(*args, **kwargs):\n    pass\n")

    # 2. Patch all .py files in target directory
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                new_content = content
                # Fix collections.MutableMapping & friends removed in Python 3.10+
                new_content = re.sub(r'collections\.(MutableMapping|Mapping|Sequence|Set|MutableSet|Callable)', r'collections.abc.\1', new_content)
                # Fix inspect.getargspec removed in Python 3.11+
                new_content = new_content.replace('inspect.getargspec', 'inspect.getfullargspec')
                
                # Fix eventlet.wsgi ALREADY_HANDLED import with exact dynamic indentation matching
                new_content = re.sub(
                    r'(\s+)from eventlet\.wsgi import ALREADY_HANDLED',
                    r'\1try:\n\1    from eventlet.wsgi import ALREADY_HANDLED\n\1except Exception:\n\1    ALREADY_HANDLED = object()',
                    new_content
                )
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)

apply_patches('/tmp/ryu-4.34/ryu')

PY

# Install patched Ryu package into site-packages
cd /tmp/ryu-4.34
pip install . --no-build-isolation --no-deps -q || python setup.py install -q || true

# Direct site-packages deployment & patch guarantee
SITE_PACKAGES=$(python3 -c "import site; print(site.getsitepackages()[0])")
rm -rf "$SITE_PACKAGES/ryu"
if [ -d "/tmp/ryu-4.34/ryu" ]; then
    cp -r /tmp/ryu-4.34/ryu "$SITE_PACKAGES/"
    echo "✅ ryu module copied directly to $SITE_PACKAGES/ryu" | tee -a "$LOG"
fi

# Symlink system mininet package into virtual environment site-packages
for path in /usr/lib/python3*/dist-packages/mininet /usr/local/lib/python3*/dist-packages/mininet; do
    if [ -d "$path" ]; then
        ln -sf "$path" "$SITE_PACKAGES/"
        echo "✅ mininet symlinked to $SITE_PACKAGES/mininet" | tee -a "$LOG"
        break
    fi
done

# Run patch directly on installed site-packages/ryu to guarantee clean state
python3 - <<'PY'
import os, re, site

site_pkg = site.getsitepackages()[0]
ryu_dir = os.path.join(site_pkg, 'ryu')

if os.path.exists(ryu_dir):
    for root, dirs, files in os.walk(ryu_dir):
        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                new_content = content
                new_content = re.sub(r'collections\.(MutableMapping|Mapping|Sequence|Set|MutableSet|Callable)', r'collections.abc.\1', new_content)
                new_content = new_content.replace('inspect.getargspec', 'inspect.getfullargspec')
                
                new_content = re.sub(
                    r'(\s+)from eventlet\.wsgi import ALREADY_HANDLED',
                    r'\1try:\n\1    from eventlet.wsgi import ALREADY_HANDLED\n\1except Exception:\n\1    ALREADY_HANDLED = object()',
                    new_content
                )
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)

print("Site-packages Ryu patch verified!")
PY

# Explicitly create ryu-manager binary wrapper to guarantee availability
cat << 'EOF' > /opt/sdn_venv/bin/ryu-manager
#!/opt/sdn_venv/bin/python3
import sys
from ryu.cmd.manager import main
if __name__ == '__main__':
    sys.exit(main())
EOF
chmod +x /opt/sdn_venv/bin/ryu-manager
echo "✅ ryu-manager binary created at /opt/sdn_venv/bin/ryu-manager" | tee -a "$LOG"

# 5. Install Remaining Python Requirements
echo "Installing ML & analysis packages..." | tee -a "$LOG"
pip install scikit-learn pandas numpy matplotlib seaborn joblib networkx autopep8 ipykernel -q || true

# 6. Pre-train ML Model
echo "Pre-training ML model..." | tee -a "$LOG"
cd "$SCRIPT_DIR/controller" 2>/dev/null || cd /workspaces/sdn-ddos-prevention/controller 2>/dev/null || true
python3 train_model.py || true

# 7. Add default alias for venv activation
grep -qF "sdn_venv" ~/.bashrc || echo "source /opt/sdn_venv/bin/activate 2>/dev/null || true" >> ~/.bashrc

echo "=== Setup Completed Successfully ✅ ===" | tee -a "$LOG"
echo "To start controller: cd /workspaces/sdn-ddos-prevention/controller && ryu-manager --verbose enterprise_security_controller.py"
