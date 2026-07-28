"""
Enterprise SDN Security Controller
Inherits from Ryu SimpleSwitch13 for robust L2 forwarding
Implements ML Detection, Dynamic Segmentation, and Automated Containment
"""

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp, ether_types
from ryu.lib import hub
import time
import pickle
import numpy as np
from collections import defaultdict
import joblib
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnterpriseSecurityController(simple_switch_13.SimpleSwitch13):
    """
    Enterprise Security Controller extending official Ryu SimpleSwitch13
    Adds: DDoS Anomaly Detection, ML Verification, Automated Containment
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnterpriseSecurityController, self).__init__(*args, **kwargs)
        
        # Datapath management
        self.datapaths = {}
        
        # Flow statistics
        self.flow_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
        
        # Security state
        self.attack_sources = set()
        self.is_attack_active = False
        
        # Metrics collection
        self.detection_times = []
        self.containment_count = 0
        
        # Load ML model
        self.ml_model = self.load_model()
        self.scaler = self.load_scaler()
        self.model_loaded = self.ml_model is not None and self.scaler is not None
        
        # Detection thresholds
        self.PPS_THRESHOLD = 1000   # > 1000 Packets/sec indicates DDoS attack
        self.BPS_THRESHOLD = 5000000  # > 5 MB/s indicates DDoS attack
        
        # Sliding window packet rate tracker
        self.pkt_counts = defaultdict(int)
        self.last_reset = time.time()
        
        # Initialize background monitoring
        self.monitor_thread = hub.spawn(self._monitor)
        
        logger.info("✅ Enterprise Security Controller Initialized (SimpleSwitch13 Engine)")
        logger.info(f"   ML Model Loaded: {self.model_loaded}")
        logger.info(f"   Threshold Detection: Enabled (PPS > {self.PPS_THRESHOLD})")

    def load_model(self):
        """Load trained ML model"""
        try:
            with open('model.pkl', 'rb') as f:
                return pickle.load(f)
        except Exception as e:
            logger.warning(f"⚠️ Model file issue ({e}) - using threshold detection")
            return None

    def load_scaler(self):
        """Load feature scaler"""
        try:
            return joblib.load('scaler.pkl')
        except:
            return None

    def _monitor(self):
        """Traffic Monitoring Module - Periodic polling"""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(3)

    def _request_stats(self, datapath):
        """Request flow statistics from switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
        except Exception:
            pass

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Register switch datapath and invoke SimpleSwitch13 base handler"""
        super(EnterpriseSecurityController, self).switch_features_handler(ev)
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        logger.info(f"✅ Switch {datapath.id} connected and registered")

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Process flow statistics for anomaly detection"""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        for stat in body:
            try:
                match = stat.match
                ip_src = match.get('ipv4_src')
                ip_dst = match.get('ipv4_dst')
                
                if ip_src and ip_dst and ip_src != '0.0.0.0':
                    pps = stat.packet_count / max(1, stat.duration_sec)
                    bps = stat.byte_count / max(1, stat.duration_sec)
                    duration = stat.duration_sec
                    proto = match.get('ip_proto', 0)
                    
                    if ip_src not in self.attack_sources:
                        self._detect_anomaly(dpid, ip_src, ip_dst, pps, bps, duration, proto)
            except Exception:
                pass

    def _detect_anomaly(self, dpid, src_ip, dst_ip, pps, bps, duration, proto):
        """Anomaly Detection Module"""
        start_time = time.time()
        
        if src_ip in self.attack_sources:
            return
            
        is_anomaly = False
        anomaly_reason = ""
        
        if pps > self.PPS_THRESHOLD:
            is_anomaly = True
            anomaly_reason = f"High PPS: {pps:.0f}"
            
        if bps > self.BPS_THRESHOLD:
            is_anomaly = True
            anomaly_reason = f"High BPS: {bps/1024/1024:.1f} MB/s"
            
        if is_anomaly and self.model_loaded:
            features = np.array([[
                pps / 1000,
                bps / 10000000,
                min(duration / 60, 1.0),
                1.0,
                1 if proto == 6 else 0,
                1 if proto == 17 else 0,
                1 if proto == 1 else 0
            ]])
            
            try:
                features_scaled = self.scaler.transform(features)
                prediction = self.ml_model.predict(features_scaled)
                confidence = np.max(self.ml_model.predict_proba(features_scaled))
                
                if prediction[0] == 1 and confidence > 0.7:
                    is_anomaly = True
                    anomaly_reason = f"ML detection (conf: {confidence:.2f})"
                    logger.warning(f"🤖 ML Confirms Attack: {src_ip} -> {dst_ip}")
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
        
        if is_anomaly:
            detection_time = time.time() - start_time
            self.detection_times.append(detection_time)
            
            logger.warning(f"⚠️ DDoS Attack Detected: {src_ip} -> {dst_ip}")
            logger.warning(f"   Reason: {anomaly_reason}")
            
            self._trigger_containment(dpid, src_ip, dst_ip, anomaly_reason)

    def _trigger_containment(self, dpid, src_ip, dst_ip, reason):
        """Automated Containment Manager"""
        self.containment_count += 1
        self.is_attack_active = True
        
        logger.info(f"🔒 Triggering Containment for {src_ip}")
        logger.info(f"   Reason: {reason}")
        
        # Block attacker traffic on all datapaths with high priority (priority 200)
        for dp in list(self.datapaths.values()):
            self._block_traffic(dp, src_ip)
            
        self.attack_sources.add(src_ip)
        logger.info(f"✅ Containment Complete for {src_ip}")

    def _block_traffic(self, datapath, src_ip):
        """Block all traffic from source using high priority drop rules"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # Drop
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=200,
            match=match,
            instructions=inst,
            idle_timeout=600,
            hard_timeout=0
        )
        datapath.send_msg(mod)
        logger.info(f"🚫 {src_ip} blocked on switch {datapath.id}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets for anomaly inspection, then delegate to SimpleSwitch13"""
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            src_ip = ip_pkt.src_ip
            dst_ip = ip_pkt.dst_ip
            proto = ip_pkt.proto
            
            now = time.time()
            if now - self.last_reset > 1.0:
                self.pkt_counts.clear()
                self.last_reset = now
                
            self.pkt_counts[src_ip] += 1
            real_pps = self.pkt_counts[src_ip]
            
            if src_ip not in self.attack_sources and real_pps > self.PPS_THRESHOLD:
                self._detect_anomaly(msg.datapath.id, src_ip, dst_ip, real_pps, 5000000, 1, proto)
                
        # Pass packet to Ryu SimpleSwitch13 base handler for 100% reliable L2 forwarding
        super(EnterpriseSecurityController, self)._packet_in_handler(ev)

if __name__ == '__main__':
    from ryu.cmd.manager import main
    import sys
    sys.argv = ['ryu-manager', __file__]
    main()
