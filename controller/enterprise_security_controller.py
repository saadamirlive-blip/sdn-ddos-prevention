"""
Enterprise SDN Security Controller
Implements ML-based Detection, Dynamic Segmentation, and Automated Containment
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp, arp
from ryu.lib import hub
import time
import pickle
import numpy as np
from collections import defaultdict
import joblib
import logging
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnterpriseSecurityController(app_manager.RyuApp):
    """
    SDN Security Controller for Enterprise Network
    Implements: ML-based Detection, Dynamic Segmentation, Automated Containment
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EnterpriseSecurityController, self).__init__(*args, **kwargs)
        
        # Store datapaths
        self.datapaths = {}
        
        # Flow statistics
        self.flow_stats = defaultdict(lambda: defaultdict(int))
        self.flow_history = defaultdict(list)
        
        # Security state
        self.attack_sources = set()
        self.quarantine_hosts = []
        self.containment_policies = {}
        self.is_attack_active = False
        self.attack_start_time = None
        
        # Metrics collection
        self.detection_times = []
        self.containment_times = []
        self.containment_count = 0
        self.false_containments = 0
        self.total_legitimate = 0
        self.available_services = 13  # Total hosts
        self.total_services = 13
        
        # Attack severity tracking
        self.attack_severity = {}
        self.containment_strategies = {}
        
        # Load ML model
        self.ml_model = self.load_model()
        self.scaler = self.load_scaler()
        self.model_loaded = self.ml_model is not None and self.scaler is not None
        
        # Detection thresholds
        self.PPS_THRESHOLD = 5000
        self.BPS_THRESHOLD = 10000000  # 10 MB/s
        self.ATTACK_DURATION_THRESHOLD = 10  # seconds
        
        # Initialize monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        self.stats_collector_thread = hub.spawn(self._collect_stats)
        
        logger.info("✅ Enterprise Security Controller Initialized")
        logger.info(f"   ML Model Loaded: {self.model_loaded}")
        logger.info(f"   Threshold Detection: Enabled")

    def load_model(self):
        """Load trained ML model"""
        try:
            with open('model.pkl', 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            logger.warning("⚠️ Model file not found - using threshold detection only")
            return None
        except Exception as e:
            logger.error(f"⚠️ Error loading model: {e}")
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
            hub.sleep(3)  # 3-second polling interval

    def _collect_stats(self):
        """Background statistics collection"""
        while True:
            total_pps = 0
            total_bps = 0
            
            for dpid, stats in self.flow_stats.items():
                for key, values in stats.items():
                    total_pps += values.get('pps', 0)
                    total_bps += values.get('bps', 0)
            
            if total_pps > self.PPS_THRESHOLD:
                logger.debug(f"High traffic: {total_pps:.0f} PPS, {total_bps/1024/1024:.1f} MB/s")
            
            hub.sleep(5)

    def _request_stats(self, datapath):
        """Request flow statistics from switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)
        except Exception as e:
            logger.debug(f"Error requesting stats from {datapath.id}: {e}")

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
                    pps = stat.packet_count / 3
                    bps = stat.byte_count / 3
                    duration = stat.duration_sec
                    proto = match.get('ip_proto', 0)
                    
                    flow_key = f"{ip_src}->{ip_dst}"
                    self.flow_stats[dpid][flow_key] = {
                        'pps': pps,
                        'bps': bps,
                        'packet_count': stat.packet_count,
                        'byte_count': stat.byte_count,
                        'duration': duration,
                        'proto': proto,
                        'timestamp': time.time()
                    }
                    
                    self.flow_history[flow_key].append({
                        'pps': pps,
                        'bps': bps,
                        'duration': duration
                    })
                    if len(self.flow_history[flow_key]) > 10:
                        self.flow_history[flow_key].pop(0)
                    
                    if ip_src not in self.attack_sources:
                        self._detect_anomaly(dpid, ip_src, ip_dst, pps, bps, duration, proto)
                    
            except Exception as e:
                logger.debug(f"Error processing stats: {e}")

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
            
        src_protos = set()
        for key, stats in self.flow_stats[dpid].items():
            if key.startswith(src_ip):
                src_protos.add(stats.get('proto', 0))
        
        if len(src_protos) >= 3:
            is_anomaly = True
            anomaly_reason = "Multi-protocol attack"
        
        if is_anomaly and self.model_loaded:
            features = np.array([[
                pps / 1000,
                bps / 10000000,
                min(duration / 60, 1.0),
                len(self.flow_history.get(f"{src_ip}->{dst_ip}", [])) / 10,
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
                else:
                    self.false_containments += 1
                    is_anomaly = False
                    
            except Exception as e:
                logger.error(f"ML prediction error: {e}")
        
        if is_anomaly:
            detection_time = time.time() - start_time
            self.detection_times.append(detection_time)
            
            logger.warning(f"⚠️ Attack Detected: {src_ip} -> {dst_ip}")
            logger.warning(f"   Reason: {anomaly_reason}")
            logger.warning(f"   Detection Time: {detection_time:.3f}s")
            
            self._trigger_containment(dpid, src_ip, dst_ip, anomaly_reason)

    def _trigger_containment(self, dpid, src_ip, dst_ip, reason):
        """Automated Containment Policy Manager"""
        start_time = time.time()
        self.containment_count += 1
        self.is_attack_active = True
        
        severity = self._calculate_severity(src_ip)
        self.attack_severity[src_ip] = severity
        
        logger.info(f"🔒 Triggering Containment for {src_ip}")
        logger.info(f"   Severity: {severity:.2f}")
        logger.info(f"   Reason: {reason}")
        
        strategy = self._select_strategy(severity)
        self.containment_strategies[src_ip] = strategy
        logger.info(f"   Strategy: {strategy}")
        
        # Apply high priority block rule across all datapaths
        for dp in self.datapaths.values():
            if strategy == 'block':
                self._block_traffic(dp.id, src_ip)
            elif strategy == 'quarantine':
                self._quarantine_host(dp.id, src_ip)
            elif strategy == 'rate_limit':
                self._rate_limit_attack(dp.id, src_ip)
            elif strategy == 'monitor':
                self._monitor_suspicious(src_ip)
        
        containment_time = time.time() - start_time
        self.containment_times.append(containment_time)
        
        self.available_services = self._count_available_services()
        self.attack_sources.add(src_ip)
        
        logger.info(f"✅ Containment Complete: {containment_time:.3f}s")

    def _calculate_severity(self, src_ip):
        """Calculate attack severity (0-1)"""
        pps_values = []
        bps_values = []
        duration_values = []
        
        for dpid, stats in self.flow_stats.items():
            for key, values in stats.items():
                if key.startswith(src_ip):
                    pps_values.append(values.get('pps', 0))
                    bps_values.append(values.get('bps', 0))
                    duration_values.append(values.get('duration', 0))
        
        if not pps_values:
            return 0.5
        
        avg_pps = np.mean(pps_values)
        avg_bps = np.mean(bps_values)
        avg_duration = np.mean(duration_values)
        
        pps_score = min(avg_pps / 20000, 1.0)
        bps_score = min(avg_bps / 50000000, 1.0)
        duration_score = min(avg_duration / 60, 1.0)
        
        severity = (pps_score * 0.4) + (bps_score * 0.3) + (duration_score * 0.3)
        return min(severity, 1.0)

    def _select_strategy(self, severity):
        """Select containment strategy based on severity"""
        if severity > 0.8:
            return 'block'
        elif severity > 0.6:
            return 'quarantine'
        elif severity > 0.4:
            return 'rate_limit'
        else:
            return 'monitor'

    def _block_traffic(self, dpid, src_ip):
        """Block all traffic from source with high priority drop rules"""
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # High priority drop rule (Priority 200)
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # Empty actions = DROP
        self._add_flow(datapath, 200, match, actions, idle_timeout=600)
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
        actions = []  # Empty actions = DROP
        self._add_flow(datapath, 200, match, actions, idle_timeout=600)
        
        logger.info(f"🚫 {src_ip} blocked on switch {dpid}")

    def _quarantine_host(self, dpid, src_ip):
        """Redirect traffic to quarantine segment"""
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = [parser.OFPActionOutput(3)]
        self._add_flow(datapath, 150, match, actions, idle_timeout=180)
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=src_ip)
        actions = [parser.OFPActionOutput(3)]
        self._add_flow(datapath, 150, match, actions, idle_timeout=180)
        
        self.quarantine_hosts.append(src_ip)
        logger.info(f"🔀 {src_ip} redirected to quarantine segment on switch {dpid}")

    def _rate_limit_attack(self, dpid, src_ip):
        """Apply rate limiting to attack traffic"""
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        meter_id = len(self.containment_strategies) + 1
        
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=[parser.OFPMeterBandDrop(rate=100, burst_size=50)]
        )
        datapath.send_msg(meter_mod)
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = [parser.OFPActionMeter(meter_id)]
        self._add_flow(datapath, 100, match, actions, idle_timeout=180)
        
        logger.info(f"⚡ {src_ip} rate-limited to 100 Kbps on switch {dpid}")

    def _monitor_suspicious(self, src_ip):
        """Monitor suspicious traffic without immediate action"""
        logger.info(f"🔍 Monitoring suspicious traffic from {src_ip}")

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0):
        """Install flow rule on switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=0
        )
        datapath.send_msg(mod)

    def _count_available_services(self):
        """Count currently available services/hosts"""
        total_hosts = self.total_services
        attack_hosts = len(self.attack_sources)
        return total_hosts - attack_hosts

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connection and setup default forwarding + packet inspection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.datapaths[datapath.id] = datapath
        
        # Priority 1: Default NORMAL L2/L3 forwarding
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self._add_flow(datapath, 1, match, actions, idle_timeout=0)
        
        # Priority 2: Forward IPv4 packet headers to Controller for ML monitoring
        match_ip = parser.OFPMatch(eth_type=0x0800)
        actions_ip = [
            parser.OFPActionOutput(ofproto.OFPP_NORMAL),
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self._add_flow(datapath, 2, match_ip, actions_ip, idle_timeout=0)
        
        logger.info(f"✅ Switch {datapath.id} connected with NORMAL forwarding and ML inspection")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming IPv4 packets for ML anomaly analysis"""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if ip_pkt:
            src_ip = ip_pkt.src_ip
            dst_ip = ip_pkt.dst_ip
            proto = ip_pkt.proto
            
            # Anomaly check for non-blocked sources
            if src_ip not in self.attack_sources:
                # Update flow statistics
                flow_key = f"{src_ip}->{dst_ip}"
                self.flow_stats[dpid][flow_key]['pps'] += 1
                self.flow_stats[dpid][flow_key]['proto'] = proto
                
                # Check for attack signatures (e.g. hping3 flood)
                if self.flow_stats[dpid][flow_key]['pps'] > 20 or proto in [1, 6, 17]:
                    self._detect_anomaly(dpid, src_ip, dst_ip, self.flow_stats[dpid][flow_key]['pps'] * 100, 1000000, 1, proto)

    def get_metrics(self):
        """Get current performance metrics"""
        avg_detection = np.mean(self.detection_times) if self.detection_times else 0
        avg_containment = np.mean(self.containment_times) if self.containment_times else 0
        
        total_incidents = len(self.attack_sources) + (self.containment_count if self.containment_count > 0 else 0)
        containment_rate = (self.containment_count / max(1, total_incidents)) * 100
        false_rate = (self.false_containments / max(1, self.total_legitimate)) * 100
        availability = (self.available_services / self.total_services) * 100
        avg_response = avg_detection + avg_containment
        
        return {
            'containment_rate': min(containment_rate, 100),
            'avg_detection_time': avg_detection,
            'avg_containment_time': avg_containment,
            'avg_response_time': avg_response,
            'false_containment_rate': false_rate,
            'network_availability': availability,
            'attacks_contained': len(self.attack_sources),
            'total_incidents': total_incidents,
            'attack_sources': list(self.attack_sources)
        }

if __name__ == '__main__':
    from ryu.cmd.manager import main
    import sys
    sys.argv = ['ryu-manager', __file__]
    main()
