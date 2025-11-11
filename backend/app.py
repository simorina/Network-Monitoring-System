from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import socket
import time
from datetime import datetime
from collections import defaultdict, deque
import subprocess
import re
import platform
from threading import Lock, Thread
import logging

# Import Scapy per packet capture
try:
    from scapy.all import sniff, IP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Install with: pip install scapy")

app = Flask(__name__)
CORS(app)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Thread-safe locks
stats_lock = Lock()
devices_lock = Lock()
packet_lock = Lock()

# Store previous network stats for interface
previous_interface_stats = {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'time': time.time()
}

# Store per-device statistics
device_traffic = defaultdict(lambda: {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'last_seen': time.time(),
    'prev_bytes_sent': 0,
    'prev_bytes_recv': 0,
    'prev_time': time.time(),
    'bandwidth_history': deque(maxlen=5),
    'bandwidth_total': 0,
    'bandwidth_sent': 0,
    'bandwidth_recv': 0,
    'is_active': False,
    'hostname': None,
    'mac': None,
    'first_seen': time.time()
})

# Cache for discovered devices
discovered_devices = {}
last_quick_scan = 0
last_deep_scan = 0

# Scanning intervals
QUICK_SCAN_INTERVAL = 10  # Quick scan ogni 10 secondi
DEEP_SCAN_INTERVAL = 600  # Deep scan ogni 10 minuti
CACHE_TIMEOUT = 900

# Packet sniffing control
sniffer_thread = None
sniffer_running = False
packet_count = 0

# Bandwidth calculator thread
bandwidth_thread = None
bandwidth_running = False

# Device scanner thread
scanner_thread = None
scanner_running = False


def get_local_ip():
    """Get the local IP address of the machine"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_network_prefix():
    """Auto-detect network prefix"""
    local_ip = get_local_ip()
    parts = local_ip.split('.')
    return '.'.join(parts[:3])


def get_network_interface():
    """Get the active network interface"""
    try:
        local_ip = get_local_ip()
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    return interface
        
        if SCAPY_AVAILABLE:
            interfaces = get_if_list()
            for iface in interfaces:
                if 'Loopback' not in iface and 'lo' not in iface.lower():
                    return iface
                    
    except Exception as e:
        logger.error(f"⚠️ Error getting network interface: {e}")
    
    return None


def get_mac_address(ip):
    """Get MAC address for an IP using ARP"""
    try:
        output = subprocess.check_output(
            f"arp -a {ip}",
            shell=True,
            timeout=1,
            creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == 'Windows' else 0
        ).decode('utf-8', errors='ignore')
        
        mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
        match = re.search(mac_pattern, output)
        if match:
            return match.group(0).replace('-', ':').upper()
    except:
        pass
    
    return "N/A"


def get_hostname_by_ip(ip):
    """Try to get hostname for an IP address"""
    try:
        socket.setdefaulttimeout(0.5)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return f"Device-{ip.split('.')[-1]}"
    finally:
        socket.setdefaulttimeout(None)


def get_arp_table():
    """Get all devices from ARP table"""
    devices_info = {}
    network_prefix = get_network_prefix()
    
    try:
        system = platform.system().lower()
        
        if system == "windows":
            output = subprocess.check_output(
                "arp -a",
                shell=True,
                timeout=2,
                creationflags=subprocess.CREATE_NO_WINDOW
            ).decode('utf-8', errors='ignore')
            
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})"
            matches = re.findall(pattern, output)
            
            for ip, mac in matches:
                if ip.startswith(f'{network_prefix}.') and not ip.endswith('.255'):
                    devices_info[ip] = mac.replace('-', ':').upper()
        else:
            try:
                output = subprocess.check_output("arp -an", shell=True, timeout=2).decode('utf-8', errors='ignore')
            except:
                output = subprocess.check_output("ip neighbor show", shell=True, timeout=2).decode('utf-8', errors='ignore')
            
            pattern = r"(\d+\.\d+\.\d+\.\d+).*?([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
            matches = re.findall(pattern, output)
            
            for ip, mac in matches:
                if ip.startswith(f'{network_prefix}.') and not ip.endswith('.255'):
                    devices_info[ip] = mac.upper()
                    
    except Exception as e:
        logger.error(f"⚠️ ARP table error: {e}")
    
    return devices_info


def quick_scan_and_resolve():
    """Quick scan: ARP + resolve hostname per dispositivi con traffico"""
    global last_quick_scan
    
    logger.info("🔍 Quick scan started...")
    current_time = time.time()
    
    # 1. Get ARP table
    arp_devices = get_arp_table()
    local_ip = get_local_ip()
    if local_ip not in arp_devices:
        arp_devices[local_ip] = get_mac_address(local_ip)
    
    # 2. Update discovered devices
    with devices_lock:
        with packet_lock:
            # Per ogni IP con traffico, resolve hostname se non già fatto
            for ip in device_traffic.keys():
                if device_traffic[ip]['hostname'] is None:
                    mac = arp_devices.get(ip, get_mac_address(ip))
                    hostname = get_hostname_by_ip(ip)
                    
                    device_traffic[ip]['hostname'] = hostname
                    device_traffic[ip]['mac'] = mac
                    
                    logger.info(f"✅ Resolved: {hostname} ({ip}) - MAC: {mac}")
                
                # Aggiungi a discovered_devices
                if ip not in discovered_devices:
                    discovered_devices[ip] = {
                        'ip': ip,
                        'mac': device_traffic[ip]['mac'] or arp_devices.get(ip, 'N/A'),
                        'hostname': device_traffic[ip]['hostname'] or f"Device-{ip.split('.')[-1]}",
                        'last_seen': current_time,
                        'is_active': True,
                        'first_seen': device_traffic[ip]['first_seen']
                    }
                else:
                    discovered_devices[ip]['last_seen'] = current_time
                    discovered_devices[ip]['is_active'] = True
    
    last_quick_scan = current_time
    logger.info(f"✅ Quick scan complete: {len(discovered_devices)} devices")


def deep_scan():
    """Deep scan completo (solo per refresh periodico)"""
    global last_deep_scan
    
    logger.info("🔍 DEEP scan started (full network sweep)...")
    current_time = time.time()
    
    # ARP scan completo
    arp_devices = get_arp_table()
    local_ip = get_local_ip()
    arp_devices[local_ip] = get_mac_address(local_ip)
    
    with devices_lock:
        for ip, mac in arp_devices.items():
            if ip not in discovered_devices:
                hostname = get_hostname_by_ip(ip)
                discovered_devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'last_seen': current_time,
                    'is_active': True,
                    'first_seen': current_time
                }
                logger.info(f"🆕 New device: {hostname} ({ip})")
            else:
                discovered_devices[ip]['last_seen'] = current_time
                discovered_devices[ip]['is_active'] = True
        
        # Remove stale
        stale = [ip for ip, data in discovered_devices.items() 
                 if current_time - data['last_seen'] > CACHE_TIMEOUT]
        for ip in stale:
            logger.info(f"❌ Timeout: {ip}")
            del discovered_devices[ip]
    
    last_deep_scan = current_time
    logger.info(f"✅ Deep scan complete: {len(discovered_devices)} devices")


def device_scanner_thread():
    """Thread che gestisce gli scan"""
    global scanner_running
    
    logger.info("🔄 Device scanner thread started")
    
    # ✅ Initial QUICK scan (immediato)
    quick_scan_and_resolve()
    
    while scanner_running:
        try:
            current_time = time.time()
            
            # Deep scan ogni 10 minuti
            if last_deep_scan == 0 or (current_time - last_deep_scan >= DEEP_SCAN_INTERVAL):
                deep_scan()
            # Quick scan ogni 10 secondi
            elif current_time - last_quick_scan >= QUICK_SCAN_INTERVAL:
                quick_scan_and_resolve()
            
            time.sleep(2)
            
        except Exception as e:
            logger.error(f"❌ Scanner error: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(2)
    
    logger.info("🛑 Device scanner stopped")


def start_device_scanner():
    """Start device scanner thread"""
    global scanner_running, scanner_thread
    
    if scanner_running:
        return
    
    scanner_running = True
    scanner_thread = Thread(target=device_scanner_thread, daemon=True)
    scanner_thread.start()


def stop_device_scanner():
    """Stop device scanner"""
    global scanner_running
    scanner_running = False


def packet_callback(packet):
    """Callback per OGNI pacchetto catturato"""
    global packet_count
    
    try:
        if IP in packet:
            packet_count += 1
            
            if packet_count % 1000 == 0:
                logger.info(f"📦 Captured {packet_count} packets")
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)
            network_prefix = get_network_prefix()
            
            with packet_lock:
                # Traffico in USCITA
                if src_ip.startswith(f'{network_prefix}.'):
                    device_traffic[src_ip]['bytes_sent'] += packet_size
                    device_traffic[src_ip]['packets_sent'] += 1
                    device_traffic[src_ip]['last_seen'] = time.time()
                
                # Traffico in ENTRATA
                if dst_ip.startswith(f'{network_prefix}.'):
                    device_traffic[dst_ip]['bytes_recv'] += packet_size
                    device_traffic[dst_ip]['packets_recv'] += 1
                    device_traffic[dst_ip]['last_seen'] = time.time()
                    
    except Exception as e:
        logger.error(f"❌ Packet callback error: {e}")


def packet_sniffer():
    """Thread che cattura i pacchetti"""
    global sniffer_running
    
    if not SCAPY_AVAILABLE:
        logger.error("❌ Scapy not available!")
        return
    
    interface = get_network_interface()
    
    if not interface:
        logger.error("❌ No network interface found!")
        return
    
    logger.info(f"🔍 Starting packet sniffer on: {interface}")
    
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            filter="ip",
            stop_filter=lambda x: not sniffer_running
        )
        
    except PermissionError:
        logger.error("❌ Permission denied! Run as Administrator")
    except Exception as e:
        logger.error(f"❌ Sniffer error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sniffer_running = False
        logger.info("🛑 Packet sniffer stopped")


def bandwidth_calculator():
    """Thread che calcola bandwidth ogni secondo"""
    global bandwidth_running
    
    logger.info("🔄 Bandwidth calculator started")
    
    while bandwidth_running:
        try:
            current_time = time.time()
            
            with packet_lock:
                for ip, traffic in list(device_traffic.items()):
                    if traffic['bytes_sent'] == 0 and traffic['bytes_recv'] == 0:
                        continue
                    
                    time_delta = current_time - traffic['prev_time']
                    
                    if time_delta >= 0.9:
                        bytes_sent_delta = max(0, traffic['bytes_sent'] - traffic['prev_bytes_sent'])
                        bytes_recv_delta = max(0, traffic['bytes_recv'] - traffic['prev_bytes_recv'])
                        
                        bandwidth_sent = bytes_sent_delta / time_delta
                        bandwidth_recv = bytes_recv_delta / time_delta
                        bandwidth_total = bandwidth_sent + bandwidth_recv
                        
                        # Smoothing
                        traffic['bandwidth_history'].append(bandwidth_total)
                        smoothed_bw = sum(traffic['bandwidth_history']) / len(traffic['bandwidth_history'])
                        
                        traffic['bandwidth_total'] = smoothed_bw
                        traffic['bandwidth_sent'] = bandwidth_sent
                        traffic['bandwidth_recv'] = bandwidth_recv
                        
                        traffic['prev_bytes_sent'] = traffic['bytes_sent']
                        traffic['prev_bytes_recv'] = traffic['bytes_recv']
                        traffic['prev_time'] = current_time
            
            time.sleep(1.0)
            
        except Exception as e:
            logger.error(f"❌ Bandwidth calculator error: {e}")
    
    logger.info("🛑 Bandwidth calculator stopped")


def start_packet_sniffer():
    """Start packet sniffer thread"""
    global sniffer_running, sniffer_thread
    
    if not SCAPY_AVAILABLE:
        logger.error("❌ Scapy not installed")
        return False
    
    if sniffer_running:
        return True
    
    sniffer_running = True
    sniffer_thread = Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()
    return True


def stop_packet_sniffer():
    """Stop packet sniffer"""
    global sniffer_running
    sniffer_running = False


def start_bandwidth_calculator():
    """Start bandwidth calculator thread"""
    global bandwidth_running, bandwidth_thread
    
    if bandwidth_running:
        return
    
    bandwidth_running = True
    bandwidth_thread = Thread(target=bandwidth_calculator, daemon=True)
    bandwidth_thread.start()


def stop_bandwidth_calculator():
    """Stop bandwidth calculator"""
    global bandwidth_running
    bandwidth_running = False


def get_network_stats():
    """Get total network statistics"""
    interface = get_network_interface()
    
    if not interface:
        return {'total_bytes_sent': 0, 'total_bytes_recv': 0, 'total_bandwidth': 0}
    
    try:
        net_io = psutil.net_io_counters(pernic=True).get(interface)
        
        if not net_io:
            return {'total_bytes_sent': 0, 'total_bytes_recv': 0, 'total_bandwidth': 0}
        
        current_time = time.time()
        
        with stats_lock:
            time_delta = current_time - previous_interface_stats['time']
            
            if time_delta > 0:
                sent_per_sec = (net_io.bytes_sent - previous_interface_stats['bytes_sent']) / time_delta
                recv_per_sec = (net_io.bytes_recv - previous_interface_stats['bytes_recv']) / time_delta
                total_bandwidth = max(0, sent_per_sec + recv_per_sec)
                
                previous_interface_stats['bytes_sent'] = net_io.bytes_sent
                previous_interface_stats['bytes_recv'] = net_io.bytes_recv
                previous_interface_stats['time'] = current_time
            else:
                total_bandwidth = 0
        
        return {
            'total_bytes_sent': net_io.bytes_sent,
            'total_bytes_recv': net_io.bytes_recv,
            'total_bandwidth': total_bandwidth
        }
        
    except Exception as e:
        logger.error(f"⚠️ Error getting network stats: {e}")
        return {'total_bytes_sent': 0, 'total_bytes_recv': 0, 'total_bandwidth': 0}


def get_connected_devices():
    """Get list of connected devices with traffic data"""
    devices = []
    
    total_bandwidth_all_devices = 0
    
    with devices_lock:
        with packet_lock:
            for ip, device_info in discovered_devices.items():
                traffic = device_traffic.get(ip, {})
                
                devices.append({
                    'ip': ip,
                    'mac': device_info.get('mac', 'N/A'),
                    'hostname': device_info.get('hostname', f"Device-{ip.split('.')[-1]}"),
                    'bytes_sent': traffic.get('bytes_sent', 0),
                    'bytes_recv': traffic.get('bytes_recv', 0),
                    'packets_sent': traffic.get('packets_sent', 0),
                    'packets_recv': traffic.get('packets_recv', 0),
                    'bandwidth_used': traffic.get('bandwidth_total', 0),
                    'bandwidth_sent': traffic.get('bandwidth_sent', 0),
                    'bandwidth_recv': traffic.get('bandwidth_recv', 0),
                    'is_active': device_info.get('is_active', False),
                    'first_seen': device_info.get('first_seen', 0)
                })
                
                total_bandwidth_all_devices += traffic.get('bandwidth_total', 0)
    
    return devices, total_bandwidth_all_devices


@app.route('/api/network-stats', methods=['GET'])
def network_stats():
    """API endpoint to get network statistics"""
    try:
        stats = get_network_stats()
        devices, total_device_bandwidth = get_connected_devices()
        
        return jsonify({
            'total_bandwidth': stats['total_bandwidth'],
            'total_bandwidth_system': stats['total_bandwidth'],
            'total_bandwidth_devices': total_device_bandwidth,
            'devices': devices,
            'timestamp': datetime.utcnow().isoformat(),
            'cached_devices': len(discovered_devices),
            'sniffer_active': sniffer_running,
            'scanner_active': scanner_running,
            'packets_captured': packet_count,
            'scapy_available': SCAPY_AVAILABLE,
            'last_deep_scan': datetime.fromtimestamp(last_deep_scan).isoformat() if last_deep_scan > 0 else None,
            'next_deep_scan_in': int(DEEP_SCAN_INTERVAL - (time.time() - last_deep_scan)) if last_deep_scan > 0 else 0
        })
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'platform': f'{platform.system()} {platform.release()}',
        'network': f'{get_network_prefix()}.0/24',
        'interface': get_network_interface(),
        'local_ip': get_local_ip(),
        'devices_discovered': len(discovered_devices),
        'sniffer_running': sniffer_running,
        'scanner_running': scanner_running,
        'scapy_available': SCAPY_AVAILABLE,
        'packets_captured': packet_count
    })


@app.route('/api/debug', methods=['GET'])
def debug():
    """Debug endpoint"""
    interface = get_network_interface()
    net_io = psutil.net_io_counters(pernic=True).get(interface) if interface else None
    
    with packet_lock:
        traffic_data = {
            ip: {
                'hostname': data.get('hostname', ip),
                'mac': data.get('mac', 'N/A'),
                'bytes_sent': data['bytes_sent'],
                'bytes_recv': data['bytes_recv'],
                'packets_sent': data['packets_sent'],
                'packets_recv': data['packets_recv'],
                'bandwidth_total': data['bandwidth_total'],
                'bandwidth_history': list(data['bandwidth_history']),
                'is_active': data['is_active']
            }
            for ip, data in device_traffic.items()
        }
    
    return jsonify({
        'platform': platform.system(),
        'scapy_available': SCAPY_AVAILABLE,
        'sniffer_running': sniffer_running,
        'scanner_running': scanner_running,
        'packets_captured': packet_count,
        'interface': interface,
        'interface_stats': {
            'bytes_sent': net_io.bytes_sent if net_io else 0,
            'bytes_recv': net_io.bytes_recv if net_io else 0
        } if net_io else {},
        'devices_count': len(device_traffic),
        'discovered_devices_count': len(discovered_devices),
        'traffic_data': traffic_data,
        'last_deep_scan': datetime.fromtimestamp(last_deep_scan).isoformat() if last_deep_scan > 0 else None,
        'last_quick_scan': datetime.fromtimestamp(last_quick_scan).isoformat() if last_quick_scan > 0 else None
    })


@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear device cache and traffic stats"""
    global discovered_devices, device_traffic, packet_count
    
    with devices_lock:
        with packet_lock:
            discovered_devices.clear()
            device_traffic.clear()
            packet_count = 0
    
    logger.info("🗑️ Cache cleared")
    return jsonify({'message': 'Cache cleared', 'status': 'ok'})


if __name__ == '__main__':
    print("=" * 70)
    print("🚀 NETWORK MONITOR v4.3 - QUICK SCAN FIXED")
    print("=" * 70)
    print(f"💻 Platform: {platform.system()} {platform.release()}")
    print(f"📡 Local IP: {get_local_ip()}")
    print(f"🌐 Network: {get_network_prefix()}.0/24")
    print(f"🔌 Interface: {get_network_interface()}")
    print()
    
    if SCAPY_AVAILABLE:
        print("✅ Scapy available - Real packet capture enabled")
    else:
        print("❌ Scapy NOT available")
    
    print()
    
    # Initialize interface stats
    interface = get_network_interface()
    if interface:
        net_io = psutil.net_io_counters(pernic=True).get(interface)
        if net_io:
            previous_interface_stats['bytes_sent'] = net_io.bytes_sent
            previous_interface_stats['bytes_recv'] = net_io.bytes_recv
            previous_interface_stats['packets_sent'] = net_io.packets_sent
            previous_interface_stats['packets_recv'] = net_io.packets_recv
            previous_interface_stats['time'] = time.time()
    
    # Start packet sniffer
    if SCAPY_AVAILABLE:
        if start_packet_sniffer():
            print("✅ Packet sniffer started")
    time.sleep(0.5)
    
    # Start bandwidth calculator
    start_bandwidth_calculator()
    time.sleep(0.5)
    
    # Start device scanner (con quick scan immediato)
    start_device_scanner()
    time.sleep(1)
    
    print("=" * 70)
    print(f"✅ API: http://localhost:5000")
    print(f"📊 Dashboard: http://localhost:3000")
    print(f"🔍 Debug: http://localhost:5000/api/debug")
    print("=" * 70)
    
    if platform.system() == 'Windows':
        print("⚠️  WINDOWS: Run as Administrator!")
    
    print("=" * 70)
    
    try:
        app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
    finally:
        stop_packet_sniffer()
        stop_bandwidth_calculator()
        stop_device_scanner()