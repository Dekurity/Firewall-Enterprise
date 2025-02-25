#!/usr/bin/env python3
import os
import sys
import re
import time
import json
import yaml
import signal
import struct
import bcrypt
import hashlib
import logging
import ipaddress
import threading
import subprocess
from datetime import datetime
from logging.handlers import RotatingFileHandler
from functools import wraps
from concurrent.futures import ThreadPoolExecutor

import netfilterqueue
import geoip2.database
import numpy as np
import pandas as pd
from scapy.all import IP, TCP, UDP, Raw 
import joblib
from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import (JWTManager, create_access_token, 
                               jwt_required, verify_jwt_in_request)
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from elasticsearch import Elasticsearch, exceptions
import boto3
from google.cloud import compute_v1
from azure.mgmt.network import NetworkManagementClient
from azure.identity import DefaultAzureCredential
from bcc import BPF
from otx import OTXv2

# ===== KONFIGURASI =====
CONFIG_PATH = '/etc/firewall/config.yaml'
RULES_PATH = '/etc/firewall/rules.yaml'
ML_MODEL_PATH = '/etc/firewall/ml_model.joblib'
DATASET_PATH = '/etc/firewall/dataset/CIC-IDS2017.csv'
EBPF_PROG = '/etc/firewall/firewall_filter.c'

try:
    with open(CONFIG_PATH) as f:
        CONFIG = yaml.safe_load(f)
except FileNotFoundError:
    print("Config file not found!")
    sys.exit(1)
except yaml.YAMLError as e:
    print(f"Error parsing config file: {e}")
    sys.exit(1)

# ===== INIT FLASK =====
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = CONFIG['jwt_secret']
app.config['BCRYPT_ROUNDS'] = 12
jwt = JWTManager(app)
csrf = CSRFProtect(app)
Talisman(app)

# ===== LOGGING TERPUSAT DENGAN FAILOVER =====
class EnhancedElasticsearchHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.es = Elasticsearch([CONFIG['elasticsearch_host']])
        self.file_handler = RotatingFileHandler(
            '/var/log/firewall.log',
            maxBytes=10*1024*1024,
            backupCount=5
        )
        self.executor = ThreadPoolExecutor(max_workers=2)
        
    def emit(self, record):
        self.executor.submit(self._emit, record)
        
    def _emit(self, record):
        log_entry = self.format(record)
        try:
            self.es.index(
                index="firewall-logs",
                body={
                    "@timestamp": datetime.utcnow().isoformat(),
                    "message": log_entry,
                    "severity": record.levelname,
                    "source": "firewall"
                }
            )
        except exceptions.ElasticsearchException:
            self.file_handler.emit(record)

logger = logging.getLogger('EnterpriseFirewall')
logger.setLevel(logging.INFO)
logger.addHandler(EnhancedElasticsearchHandler())

# ===== CORE FIREWALL DENGAN eBPF OPTIMIZATION =====
class EBpfManager:
    def __init__(self):
        self.bpf = BPF(src_file=EBPF_PROG)
        self.xdp_filter = self.bpf.load_func("xdp_filter", BPF.XDP)
        self.bpf.attach_xdp(dev=CONFIG['network_interface'], fn=self.xdp_filter)
        self.block_table = self.bpf["block_table"]
        
    def update_blocklist(self, ips):
        for ip in ips:
            packed_ip = struct.pack("!I", int(ipaddress.IPv4Address(ip)))
            self.block_table[struct.pack('I', int(ip))] = self.bpf.Table.Leaf(1)

# ===== MACHINE LEARNING ENGINE =====
class MLEngine:
    def __init__(self):
        self.scaler = StandardScaler()
        self._load_model()
        
    def _load_model(self):
        if os.path.exists(ML_MODEL_PATH):
            self.model, self.scaler = joblib.load(ML_MODEL_PATH)
            logger.info("Model ML dimuat dari cache")
        else:
            self._train_model()
            
    def _train_model(self):
        try:
            df = pd.read_csv(DATASET_PATH)
            features = df[['Packet Length', 'TTL', 'Protocol', 'Flags', 'Port']]
            self.scaler.fit(features)
            processed = self.scaler.transform(features)
            self.isolation_forest = IsolationForest(n_estimators=150, contamination=0.01)
            self.random_forest = RandomForestClassifier(n_estimators=100)
            self.isolation_forest.fit(processed)
            self.random_forest.fit(processed, df['Label'])
            joblib.dump((self.isolation_forest, self.random_forest, self.scaler), ML_MODEL_PATH)
            logger.info("Model dilatih dengan dataset CIC-IDS2017")
        except Exception as e:
            logger.error(f"Gagal memuat dataset: {e}")
            self._train_default_model()
            
    def _train_default_model(self):
        dummy_data = np.random.randn(10000, 5)
        self.scaler.fit(dummy_data)
        self.isolation_forest = IsolationForest(n_estimators=100)
        self.random_forest = RandomForestClassifier(n_estimators=100)
        self.isolation_forest.fit(self.scaler.transform(dummy_data))
        self.random_forest.fit(self.scaler.transform(dummy_data), np.random.randint(0, 2, 10000))
        joblib.dump((self.isolation_forest, self.random_forest, self.scaler), ML_MODEL_PATH)
        logger.warning("Model default digunakan")
        
    def predict(self, features):
        scaled = self.scaler.transform([features])
        isolation_prediction = self.isolation_forest.predict(scaled)[0]
        random_forest_prediction = self.random_forest.predict(scaled)[0]
        return isolation_prediction, random_forest_prediction

# ===== THREAT INTELLIGENCE =====
class ThreatIntelligence:
    def __init__(self):
        self.otx = OTXv2(CONFIG['otx_api_key'])
        self.blocked_ips = set()
        self._load_initial_blocklist()
        
    def _load_initial_blocklist(self):
        try:
            pulses = self.otx.getall()
            for pulse in pulses:
                for indicator in pulse['indicators']:
                    if indicator['type'] == 'IPv4':
                        self.blocked_ips.add(indicator['indicator'])
        except Exception as e:
            logger.error(f"Gagal memuat OTX: {e}")
            
    def report_ip(self, ip):
        self.blocked_ips.add(ip)
        logger.info(f"IP dilaporkan: {ip}")

# ===== CLOUD MANAGER =====
class CloudManager:
    def __init__(self):
        self.aws = boto3.client('ec2',
            aws_access_key_id=CONFIG['aws_access_key'],
            aws_secret_access_key=CONFIG['aws_secret_key'],
            region_name=CONFIG['aws_region']
        )
        self.azure = NetworkManagementClient(
            DefaultAzureCredential(),
            CONFIG['azure_sub_id']
        )
        self.gcp = compute_v1.FirewallsClient.from_service_account_json(
            CONFIG['gcp_cred_path']
        )
        self.executor = ThreadPoolExecutor(max_workers=3)
        
    def sync_rules(self, rules):
        self.executor.submit(self._sync_aws, rules)
        self.executor.submit(self._sync_azure, rules)
        self.executor.submit(self._sync_gcp, rules)
        
    def _sync_aws(self, rules):
        try:
            self.aws.authorize_security_group_ingress(
                GroupId=CONFIG['aws_sg_id'],
                IpPermissions=self._convert_rules_to_aws(rules)
            )
        except Exception as e:
            logger.error(f"AWS Sync Error: {e}")
            
    def _sync_azure(self, rules):
        try:
            nsg = self.azure.network_security_groups.get(
                CONFIG['azure_resource_group'],
                CONFIG['azure_nsg_name']
            )
            for rule in rules['security_policies']:
                nsg.security_rules.create_or_update(
                    rule['name'],
                    self._convert_rule_to_azure(rule)
                )
        except Exception as e:
            logger.error(f"Azure Sync Error: {e}")
            
    def _sync_gcp(self, rules):
        try:
            for rule in rules['security_policies']:
                firewall_rule = compute_v1.Firewall(
                    name=rule['name'],
                    direction=rule['direction'],
                    allowed=[compute_v1.Allowed(ports=rule['ports'])],
                    source_ranges=rule['source_ranges'],
                )
                self.gcp.insert(
                    project=CONFIG['gcp_project_id'],
                    firewall_resource=firewall_rule
                )
        except Exception as e:
            logger.error(f"GCP Sync Error: {e}")

# ===== API SECURITY ENHANCEMENTS =====
failed_logins = {}
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"]
)

def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['role'] != role:
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper

@app.route('/api/login', methods=['POST'])
@limiter.limit("3 per minute")
@csrf.exempt
def login():
    client_ip = get_remote_address()
    if client_ip in failed_logins and failed_logins[client_ip]['attempts'] >= 3:
        time.sleep(5)
        
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username == CONFIG['admin_user'] and bcrypt.checkpw(
        password.encode(), 
        CONFIG['admin_pw_hash'].encode()
    ):
        failed_logins.pop(client_ip, None)
        access_token = create_access_token(
            identity=username,
            additional_claims={"role": "admin"}
        )
        return jsonify(access_token=access_token)
    else:
        failed_logins[client_ip] = {
            'attempts': failed_logins.get(client_ip, {}).get('attempts', 0) + 1,
            'last_attempt': time.time()
        }
        return jsonify({"error": "Invalid credentials"}), 401

# ===== MAIN FIREWALL CORE =====
class EnterpriseFirewall:
    def __init__(self):
        self.ebpf = EBpfManager()
        self.ml = MLEngine()
        self.cloud = CloudManager()
        self.threat_intel = ThreatIntelligence()
        self._init_network()
        self._load_rules()
        
    def _init_network(self):
        subprocess.run([
            "sysctl", "-w",
            "net.netfilter.nf_conntrack_max=2000000",
            "net.ipv4.tcp_max_syn_backlog=4096",
            "net.ipv4.tcp_syncookies=1"
        ])
        subprocess.run(["ipset", "create", "blocked_ips", "hash:ip", "timeout", "86400"])
        
    def _load_rules(self):
        with open(RULES_PATH) as f:
            self.rules = yaml.safe_load(f)
            self._validate_rules()
            self.cloud.sync_rules(self.rules)

    def _validate_rules(self):
        required_sections = ['filtering', 'nat', 'security_policies']
        for section in required_sections:
            if section not in self.rules:
                raise ValueError(f"Bagian {section} tidak ada dalam aturan")

    def start(self):
        self.nf_queue = netfilterqueue.NetfilterQueue()
        self.nf_queue.bind(0, self._packet_handler)
        try:
            self.nf_queue.run()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.nf_queue.unbind()
        subprocess.run(["ipset", "destroy", "blocked_ips"])
        logger.info("Firewall dihentikan")

    def _packet_handler(self, packet):
        try:
            pkt = IP(packet.get_payload())
            if self._pre_checks(pkt):
                packet.accept()
                return
            if self._detect_threats(pkt):
                packet.drop()
                return
            packet.accept()
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")
            packet.accept()

    def _pre_checks(self, pkt):
        src_ip = pkt[IP].src
        if src_ip in self.threat_intel.blocked_ips:
            return True
        if not self.ddos_protector.check_rate(src_ip):
            self._block_ip(src_ip, "Rate limit exceeded")
            return True
        if self._check_geo_restriction(pkt):
            return True
        return False

    def _check_geo_restriction(self, pkt):
        try:
            country = self.geoip_reader.country(pkt[IP].src).country.iso_code
            if country in self.rules['security_policies']['blocked_countries']:
                self._block_ip(pkt[IP].src, f"Blocked country: {country}")
                return True
        except Exception as e:
            logger.error(f"GeoIP error: {str(e)}")
        return False

    def _detect_threats(self, pkt):
        threats = []
        if Raw in pkt:
            payload = str(pkt[Raw].load)
            threats += self._detect_signatures(payload)
        features = self._extract_features(pkt)
        isolation_prediction, random_forest_prediction = self.ml.predict(features)
        if isolation_prediction == -1 or random_forest_prediction == 1:
            threats.append("Anomalous traffic pattern")
        threats += self.state_tracker.analyze_behavior(pkt)
        if threats:
            self._handle_threat(pkt, threats)
            return True
        return False

    def _detect_signatures(self, payload):
        threats = []
        for pattern in self.rules['security_policies']['signatures']:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append(f"Malicious pattern detected: {pattern}")
        return threats

    def _extract_features(self, pkt):
        features = [
            len(pkt),
            pkt[IP].ttl,
            pkt[IP].proto,
            TCP in pkt and pkt[TCP].flags or 0,
            UDP in pkt and pkt[UDP].dport or 0
        ]
        return np.array(features)

    def _handle_threat(self, pkt, threats):
        src_ip = pkt[IP].src
        logger.warning(f"Ancaman terdeteksi dari {src_ip}: {', '.join(threats)}")
        self._block_ip(src_ip, "Threat detected: " + ", ".join(threats))
        self.cloud.block_ip(src_ip)
        self.threat_intel.report_ip(src_ip)

    def _block_ip(self, ip, reason):
        subprocess.run(["ipset", "add", "blocked_ips", ip, "timeout", "86400"])
        logger.info(f"IP diblokir: {ip} - Alasan: {reason}")

# ===== CONFIG WATCHER =====
class ConfigWatcher(FileSystemEventHandler):
    def __init__(self, path, callback):
        self.path = path
        self.callback = callback
        self.observer = Observer()

    def start(self):
        self.observer.schedule(self, self.path, recursive=False)
        self.observer.start()
        logger.info("Monitoring config file for changes...")

    def on_modified(self, event):
        if event.src_path == self.path:
            logger.info("Config file modified, reloading rules...")
            self.callback()

    def stop(self):
        self.observer.stop()
        self.observer.join()

# ===== API ENDPOINTS =====
@app.route('/api/block', methods=['POST'])
@jwt_required()
@csrf.exempt
@limiter.limit("10/minute")
def block_ip():
    ip = request.json.get('ip')
    if not re.match(r'^\d{1,3}(.\d{1,3}){3}$', ip):
        return jsonify({"error": "Format IP tidak valid"}), 400
    firewall._block_ip(ip, "Manual block via API")
    return jsonify({"status": "success", "message": f"{ip} diblokir"})

@app.route('/api/stats')
@jwt_required()
def get_stats():
    return jsonify({
        "connections": len(firewall.state_tracker.connections),
        "blocked_ips": firewall.threat_intel.blocked_count(),
        "throughput": firewall.ddos_protector.request_counts
    })

# ===== MAIN =====
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Harus dijalankan sebagai root!")
        sys.exit(1)

    firewall = EnterpriseFirewall()
    api_thread = threading.Thread(target=app.run, kwargs={'host': '0.0.0.0', 'port': 5000})
    api_thread.start()

    try:
        firewall.start()
    except Exception as e:
        logger.critical(f"Kesalahan saat menjalankan firewall: {str(e)}")
        firewall.stop()
        sys.exit(1)
    finally:
        api_thread.join()
        firewall.stop()