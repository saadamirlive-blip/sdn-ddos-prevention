# 🚀 Running the SDN Project on GitHub Codespaces

## Step 1 — Upload the Project to GitHub

### Option A: GitHub Web UI (No Git required)
1. Go to https://github.com/new
2. Create a new **public** repository, e.g. `sdn-ddos-prevention`
3. Click **"uploading an existing file"**
4. Drag and drop the entire `sdn_security_project/` folder contents
5. Click **Commit changes**

### Option B: Git CLI (Recommended)
Install Git for Windows: https://git-scm.com/download/win
Then run in Git Bash:

```bash
cd /e/SDN/sdn_security_project
git init
git add -A
git commit -m "Initial commit: SDN DDoS Prevention System"
git remote add origin https://github.com/YOUR_USERNAME/sdn-ddos-prevention.git
git branch -M main
git push -u origin main
```

### Option C: GitHub Desktop (GUI)
Download: https://desktop.github.com/
File → Add Local Repository → e:\SDN\sdn_security_project → Publish repository

---

## Step 2 — Open in GitHub Codespaces

1. Go to your repository on GitHub
2. Click the green `<> Code` button
3. Click the **Codespaces** tab
4. Click **"Create codespace on main"**

The `.devcontainer/install.sh` runs automatically and installs everything.
First build takes ~3-5 minutes.

---

## Step 3 — Run the Project (4 Terminals)

### Terminal 1 — Ryu Controller
```bash
source /opt/sdn_venv/bin/activate
cd controller
ryu-manager --verbose enterprise_security_controller.py
```

### Terminal 2 — Network Topology
```bash
source /opt/sdn_venv/bin/activate
cd topology
sudo mn -c
sudo python3 topology_enterprise.py
```

### Terminal 3 — Attack Tests (Mininet CLI)
```
mininet> h13 ping 10.0.3.1
mininet> h13 hping3 -S --flood -p 80 10.0.3.1
mininet> h13 hping3 --udp --flood -p 53 10.0.3.1
```

### Terminal 4 — Performance Plots
```bash
source /opt/sdn_venv/bin/activate
cd analysis
python3 performance_evaluation.py
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| OVS not starting | `service openvswitch-switch restart` |
| Mininet connection error | `sudo mn -c` then rerun topology |
| Ryu eventlet error | `pip install "eventlet==0.30.2" --force-reinstall` |
| Model not found | `cd controller && python3 train_model.py` |
| Port 6633 in use | `killall ryu-manager` then restart |

## Free Codespaces Quota
- Free tier: **120 hours/month**
- Stop codespace when not in use to save hours
