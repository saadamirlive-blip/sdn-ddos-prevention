"""
Enterprise Network Topology
4 OpenFlow Switches, 13 Hosts (1 Attacker)
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
import time
import sys
import socket
import subprocess
import re

class FastOVSSwitch(OVSSwitch):
    """Custom OVS Switch that uses --no-wait and --timeout=2 to prevent container freezes"""
    def vsctl(self, *args, **kwargs):
        cmd = ['ovs-vsctl', '--no-wait', '--timeout=2'] + list(args)
        return self.cmd(*cmd)

    def connected(self):
        return True

def clean_leftover_network():
    """Fast non-blocking removal of stale OVS bridges & restart OVS service"""
    try:
        subprocess.run(['service', 'openvswitch-switch', 'restart'], 
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except Exception:
        pass

    for br in ['s0', 's1', 's2', 's3']:
        try:
            subprocess.run(['ovs-vsctl', '--no-wait', '--timeout=1', '--if-exists', 'del-br', br], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
        except Exception:
            pass
            
    try:
        res = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True, timeout=2)
        ifnames = re.findall(r'\b([sh]\d+-eth\d+)\b', res.stdout)
        for ifname in set(ifnames):
            subprocess.run(['ip', 'link', 'delete', ifname], 
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1)
    except Exception:
        pass

def get_controller_port():
    """Detect if Ryu is listening on port 6653 or 6633"""
    for port in [6653, 6633]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex(('127.0.0.1', port)) == 0:
                    return port
        except Exception:
            pass
    return 6653  # Default OpenFlow 1.3 port

class EnterpriseTopo(Topo):
    """Enterprise Network Topology - 4 OpenFlow Switches, 13 Hosts"""
    
    def build(self):
        # Core Switch
        s0 = self.addSwitch('s0', cls=FastOVSSwitch)
        
        # Edge Switches
        s1 = self.addSwitch('s1', cls=FastOVSSwitch)
        s2 = self.addSwitch('s2', cls=FastOVSSwitch)
        s3 = self.addSwitch('s3', cls=FastOVSSwitch)
        
        # Edge S1 Hosts (h1-h5) - Business units (10.0.0.1 - 10.0.0.5)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:00:05')
        
        # Edge S2 Hosts (h6-h10) - Additional business units (10.0.0.6 - 10.0.0.10)
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:00:06')
        h7 = self.addHost('h7', ip='10.0.0.7/24', mac='00:00:00:00:00:07')
        h8 = self.addHost('h8', ip='10.0.0.8/24', mac='00:00:00:00:00:08')
        h9 = self.addHost('h9', ip='10.0.0.9/24', mac='00:00:00:00:00:09')
        h10 = self.addHost('h10', ip='10.0.0.10/24', mac='00:00:00:00:00:10')
        
        # Edge S3 Hosts (h11-h13) - Servers and attacker (10.0.0.11 - 10.0.0.13)
        h11 = self.addHost('h11', ip='10.0.0.11/24', mac='00:00:00:00:00:11')
        h12 = self.addHost('h12', ip='10.0.0.12/24', mac='00:00:00:00:00:12')
        h13 = self.addHost('h13', ip='10.0.0.13/24', mac='00:00:00:00:00:13')
        
        # Host labels
        self.host_labels = {
            'h1': 'Database',
            'h2': 'Finance',
            'h3': 'HR',
            'h4': 'EMP1',
            'h5': 'EMP2',
            'h6': 'APP',
            'h7': 'SALES',
            'h8': 'MET',
            'h9': 'GUEST',
            'h10': 'ADMIN',
            'h11': 'WEB',
            'h12': 'DEV',
            'h13': 'ATTACKER'
        }
        
        # Connect Core Switch to Edge Switches
        self.addLink(s0, s1)
        self.addLink(s0, s2)
        self.addLink(s0, s3)
        
        # Connect hosts to Edge S1
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s1)
        self.addLink(h5, s1)
        
        # Connect hosts to Edge S2
        self.addLink(h6, s2)
        self.addLink(h7, s2)
        self.addLink(h8, s2)
        self.addLink(h9, s2)
        self.addLink(h10, s2)
        
        # Connect hosts to Edge S3
        self.addLink(h11, s3)
        self.addLink(h12, s3)
        self.addLink(h13, s3)

def run_enterprise_simulation():
    """Run the enterprise network simulation"""
    setLogLevel('info')
    
    print("\n" + "="*70)
    print("ENTERPRISE SDN SECURITY SIMULATION")
    print("="*70)
    print("\nCleaning leftover interfaces...")
    clean_leftover_network()
    
    print("\nStarting network topology...")
    
    # Create topology
    topo = EnterpriseTopo()
    
    # Auto-detect active controller port (6653 or 6633)
    target_port = get_controller_port()
    print(f"Detected active Ryu Controller port: {target_port}")
    
    # Non-blocking Mininet topology startup with FastOVSSwitch
    net = Mininet(topo=topo, 
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=target_port),
                  switch=FastOVSSwitch,
                  waitConnected=False)
    
    # Start network
    net.start()
    
    # Populate static ARP entries for 100% instant zero-loss resolution
    print("Configuring static ARP entries on all hosts...")
    net.staticArp()
    
    # Force OpenFlow 1.3 and controller binding on detected port
    for s in ['s0', 's1', 's2', 's3']:
        subprocess.run(['ovs-vsctl', '--no-wait', 'set', 'bridge', s, 'protocols=OpenFlow13'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(['ovs-vsctl', '--no-wait', 'set-controller', s, f'tcp:127.0.0.1:{target_port}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Show topology information
    print("\n" + "-"*70)
    print("TOPOLOGY INFORMATION")
    print("-"*70)
    print("\nSwitches:")
    print("  s0 - Core Switch")
    print("  s1 - Edge S1 - Business")
    print("  s2 - Edge S2 - Business")
    print("  s3 - Edge S3 - Servers")
    
    print("\nHosts:")
    for host in net.hosts:
        label = topo.host_labels.get(host.name, host.name)
        ip = host.IP()
        print(f"  {host.name} ({label}) - {ip}")
    
    # Show controller info
    print("\n" + "-"*70)
    print("CONTROLLER INFORMATION")
    print("-"*70)
    print(f"  Ryu Controller: 127.0.0.1:{target_port}")
    print("  OpenFlow Version: 1.3")
    print("  Security Modules: ML Detection, Dynamic Segmentation, Automated Containment")
    
    print("\n" + "="*70)
    print("SIMULATION READY")
    print("="*70)
    print("\nAvailable Commands:")
    print("  1. Test Connectivity:")
    print("     h1 ping 10.0.0.11       # Ping WEB Server (h11)")
    print("     h2 ping 10.0.0.11       # Ping WEB Server (h11)")
    print("  ")
    print("  2. Generate Normal Traffic:")
    print("     h11 iperf -s &          # Start iperf server on WEB")
    print("     h1 iperf -c 10.0.0.11   # Generate client traffic")
    print("  ")
    print("  3. Launch Attacks (from h13 - Attacker):")
    print("     h13 hping3 -S --flood -p 80 10.0.0.11   # SYN Flood")
    print("     h13 hping3 --udp --flood -p 53 10.0.0.11 # UDP Flood")
    print("     h13 ping -f 10.0.0.11                   # ICMP Flood")
    print("  ")
    print("  4. Monitor Flow Rules:")
    print("     sh ovs-ofctl -O OpenFlow13 dump-flows s1")
    print("     sh ovs-ofctl -O OpenFlow13 dump-flows s3")
    print("\nType 'exit' or press Ctrl+D to end simulation")
    print("="*70)
    
    # Open CLI for interaction
    CLI(net)
    
    # Stop network
    print("\nShutting down simulation...")
    net.stop()
    print("✅ Simulation ended.")

def main():
    """Main entry point"""
    try:
        run_enterprise_simulation()
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
