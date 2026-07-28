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
        s0 = self.addSwitch('s0', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Edge Switches
        s1 = self.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
        s2 = self.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
        s3 = self.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
        
        # Edge S1 Hosts (h1-h5) - Business units
        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.1.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.1.4/24', mac='00:00:00:00:00:04')
        h5 = self.addHost('h5', ip='10.0.1.5/24', mac='00:00:00:00:00:05')
        
        # Edge S2 Hosts (h6-h10) - Additional business units
        h6 = self.addHost('h6', ip='10.0.2.1/24', mac='00:00:00:00:00:06')
        h7 = self.addHost('h7', ip='10.0.2.2/24', mac='00:00:00:00:00:07')
        h8 = self.addHost('h8', ip='10.0.2.3/24', mac='00:00:00:00:00:08')
        h9 = self.addHost('h9', ip='10.0.2.4/24', mac='00:00:00:00:00:09')
        h10 = self.addHost('h10', ip='10.0.2.5/24', mac='00:00:00:00:00:10')
        
        # Edge S3 Hosts (h11-h13) - Servers and attacker
        h11 = self.addHost('h11', ip='10.0.3.1/24', mac='00:00:00:00:00:11')
        h12 = self.addHost('h12', ip='10.0.3.2/24', mac='00:00:00:00:00:12')
        h13 = self.addHost('h13', ip='10.0.3.3/24', mac='00:00:00:00:00:13')
        
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
        self.addLink(s0, s1, bw=1000, delay='2ms')
        self.addLink(s0, s2, bw=1000, delay='2ms')
        self.addLink(s0, s3, bw=1000, delay='2ms')
        
        # Connect hosts to Edge S1
        self.addLink(h1, s1, bw=100, delay='5ms')
        self.addLink(h2, s1, bw=100, delay='5ms')
        self.addLink(h3, s1, bw=100, delay='5ms')
        self.addLink(h4, s1, bw=100, delay='5ms')
        self.addLink(h5, s1, bw=100, delay='5ms')
        
        # Connect hosts to Edge S2
        self.addLink(h6, s2, bw=100, delay='5ms')
        self.addLink(h7, s2, bw=100, delay='5ms')
        self.addLink(h8, s2, bw=100, delay='5ms')
        self.addLink(h9, s2, bw=100, delay='5ms')
        self.addLink(h10, s2, bw=100, delay='5ms')
        
        # Connect hosts to Edge S3
        self.addLink(h11, s3, bw=100, delay='5ms')
        self.addLink(h12, s3, bw=100, delay='5ms')
        self.addLink(h13, s3, bw=100, delay='5ms')

def run_enterprise_simulation():
    """Run the enterprise network simulation"""
    setLogLevel('info')
    
    print("\n" + "="*70)
    print("ENTERPRISE SDN SECURITY SIMULATION")
    print("="*70)
    print("\nStarting network topology...")
    
    # Create topology
    topo = EnterpriseTopo()
    
    # Auto-detect active controller port (6653 or 6633)
    target_port = get_controller_port()
    print(f"Connecting to Remote Controller at 127.0.0.1:{target_port}...")
    
    # Connect to Ryu controller
    net = Mininet(topo=topo, 
                  controller=lambda name: RemoteController(name, ip='127.0.0.1', port=target_port),
                  switch=OVSSwitch,
                  waitConnected=False)
    
    # Start network
    net.start()
    
    # Show topology information
    print("\n" + "-"*70)
    print("TOPOLOGY INFORMATION")
    print("-"*70)
    print("\nSwitches:")
    print("  s0 - Core Switch (1000 Mbps)")
    print("  s1 - Edge S1 (100 Mbps) - Business")
    print("  s2 - Edge S2 (100 Mbps) - Business")
    print("  s3 - Edge S3 (100 Mbps) - Servers")
    
    print("\nHosts:")
    for host in net.hosts:
        label = topo.host_labels.get(host.name, host.name)
        ip = host.IP()
        print(f"  {host.name} ({label}) - {ip}")
    
    # Configure hosts with proper routes
    for host in net.hosts:
        host.cmd('route add default gw 10.0.0.1')
    
    # Test connectivity
    print("\n" + "-"*70)
    print("Testing connectivity...")
    print("-"*70)
    net.pingAll()
    
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
    print("     h1 ping h11")
    print("     h2 ping h11")
    print("     h3 ping h11")
    print("  ")
    print("  2. Generate Normal Traffic:")
    print("     iperf -s on server (h11)")
    print("     iperf -c 10.0.3.1 on client (h1)")
    print("  ")
    print("  3. Launch Attacks (from h13 - Attacker):")
    print("     h13 hping3 -S --flood -p 80 10.0.3.1    # SYN Flood")
    print("     h13 hping3 --udp --flood -p 53 10.0.3.1  # UDP Flood")
    print("     h13 ping -f 10.0.3.1                     # ICMP Flood")
    print("  ")
    print("  4. Monitor Flow Rules:")
    print("     sh ovs-ofctl -O OpenFlow13 dump-flows s1")
    print("     sh ovs-ofctl -O OpenFlow13 dump-flows s2")
    print("     sh ovs-ofctl -O OpenFlow13 dump-flows s3")
    print("  ")
    print("  5. Monitor Metrics:")
    print("     sh ovs-ofctl -O OpenFlow13 dump-meters s1")
    print("     sh ovs-ofctl -O OpenFlow13 dump-groups s1")
    print("  ")
    print("  6. Check Controller Logs:")
    print("     (Check terminal running Ryu)")
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
