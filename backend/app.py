from flask import Flask, jsonify
from flask_cors import CORS
import psutil
import socket
import time
from datetime import datetime
from collections import defaultdict
import subprocess
import re
import platform
from threading import Lock, Thread
from scapy.all import sniff, IP, get_if_list

app = Flask(__name__)
CORS(app)

# Thread-safe locks
stats_lock = Lock()
devices_lock = Lock()
sniffer_lock = Lock()

# Store previous network stats
previous_stats = {}

# Real-time packet statistics per device WITH HISTORY
device_traffic = defaultdict(lambda: {
    'bytes_sent': 0,
    'bytes_recv': 0,
    'packets_sent': 0,
    'packets_recv': 0,
    'last_update': time.time(),
    'prev_bytes_sent': 0,  # Per calcolare delta
    'prev_bytes_recv': 0,  # Per calcolare delta
    'prev_time': time.time()  # Per calcolare bandwidth
})

# Cache for discovered devices
discovered_devices = {}
last_full_scan = 0
SCAN_INTERVAL = 300
CACHE_TIMEOUT = 600

# Packet sniffing control
sniffer_running = False
sniffer_thread = None

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
        
        # Fallback
        interfaces = get_if_list()
        for iface in interfaces:
            if iface != 'lo' and not iface.startswith('lo'):
                return iface
                
    except Exception as e:
        print(f"⚠️ Error getting network interface: {e}")
    
    return None

def get_mac_address(ip):
    """Get MAC address for an IP using ARP"""
    try:
        system = platform.system().lower()
        
        if system == "windows":
            output = subprocess.check_output(f"arp -a {ip}", shell=True, timeout=1).decode('utf-8', errors='ignore')
            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_pattern, output)
            if match:
                return match.group(0).replace('-', ':').upper()
        else:
            try:
                output = subprocess.check_output(f"arp -n {ip}", shell=True, timeout=1).decode('utf-8', errors='ignore')
            except:
                output = subprocess.check_output(f"ip neighbor show {ip}", shell=True, timeout=1).decode('utf-8', errors='ignore')
            
            mac_pattern = r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"
            match = re.search(mac_pattern, output)
            if match:
                return match.group(0).upper()
    except:
        pass
    
    return "N/A"

def get_hostname_by_ip(ip):
    """Try to get hostname for an IP address"""
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(ip)[0]
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
            output = subprocess.check_output("arp -a", shell=True, timeout=2).decode('utf-8', errors='ignore')
            pattern = r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})"
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
        print(f"⚠️ ARP table error: {e}")
    
    return devices_info

def packet_callback(packet):
    """Callback function for each captured packet"""
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)
            network_prefix = get_network_prefix()
            
            # Track outgoing traffic
            if src_ip.startswith(f'{network_prefix}.'):
                with sniffer_lock:
                    device_traffic[src_ip]['bytes_sent'] += packet_size
                    device_traffic[src_ip]['packets_sent'] += 1
                    device_traffic[src_ip]['last_update'] = time.time()
            
            # Track incoming traffic
            if dst_ip.startswith(f'{network_prefix}.'):
                with sniffer_lock:
                    device_traffic[dst_ip]['bytes_recv'] += packet_size
                    device_traffic[dst_ip]['packets_recv'] += 1
                    device_traffic[dst_ip]['last_update'] = time.time()
                    
    except Exception:
        pass

def packet_sniffer():
    """Main packet sniffing thread"""
    global sniffer_running
    
    interface = get_network_interface()
    
    if not interface:
        print("❌ No network interface found!")
        return
    
    print(f"🔍 Starting packet sniffer on interface: {interface}")
    
    try:
        sniff(
            iface=interface,
            prn=packet_callback,
            store=False,
            filter="ip",
            stop_filter=lambda x: not sniffer_running
        )
    except PermissionError:
        print("❌ Permission denied! Run as root/administrator")
    except Exception as e:
        print(f"❌ Sniffer error: {e}")
    finally:
        sniffer_running = False
        print("🛑 Packet sniffer stopped")

def start_packet_sniffer():
    """Start the packet sniffing thread"""
    global sniffer_running, sniffer_thread
    
    if sniffer_running:
        return
    
    sniffer_running = True
    sniffer_thread = Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()

def stop_packet_sniffer():
    """Stop the packet sniffing thread"""
    global sniffer_running
    sniffer_running = False

def discover_devices():
    """Fast device discovery using ARP table"""
    global discovered_devices
    
    current_time = time.time()
    arp_devices = get_arp_table()
    
    # Add local machine
    local_ip = get_local_ip()
    if local_ip not in arp_devices:
        arp_devices[local_ip] = get_mac_address(local_ip)
    
    # Update discovered devices cache
    with devices_lock:
        for ip, mac in arp_devices.items():
            if ip not in discovered_devices:
                discovered_devices[ip] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': get_hostname_by_ip(ip),
                    'last_seen': current_time
                }
            else:
                discovered_devices[ip]['last_seen'] = current_time
        
        # Remove stale devices
        stale = [ip for ip, data in discovered_devices.items() 
                 if current_time - data['last_seen'] > CACHE_TIMEOUT]
        for ip in stale:
            del discovered_devices[ip]
    
    return list(arp_devices.keys())

def calculate_bandwidth_per_device(ip):
    """Calculate REAL bandwidth per device based on packet capture"""
    with sniffer_lock:
        if ip not in device_traffic:
            return 0, 0, 0  # total, sent, recv
        
        current_time = time.time()
        prev_time = device_traffic[ip]['prev_time']
        time_delta = current_time - prev_time
        
        if time_delta < 0.5:  # Avoid too frequent updates
            # Return last calculated value
            prev_total = device_traffic[ip].get('last_bandwidth_total', 0)
            prev_sent = device_traffic[ip].get('last_bandwidth_sent', 0)
            prev_recv = device_traffic[ip].get('last_bandwidth_recv', 0)
            return prev_total, prev_sent, prev_recv
        
        # Calculate deltas
        current_bytes_sent = device_traffic[ip]['bytes_sent']
        current_bytes_recv = device_traffic[ip]['bytes_recv']
        prev_bytes_sent = device_traffic[ip]['prev_bytes_sent']
        prev_bytes_recv = device_traffic[ip]['prev_bytes_recv']
        
        bytes_sent_delta = current_bytes_sent - prev_bytes_sent
        bytes_recv_delta = current_bytes_recv - prev_bytes_recv
        
        # Calculate bandwidth (bytes per second)
        bandwidth_sent = bytes_sent_delta / time_delta
        bandwidth_recv = bytes_recv_delta / time_delta
        bandwidth_total = bandwidth_sent + bandwidth_recv
        
        # Update previous values
        device_traffic[ip]['prev_bytes_sent'] = current_bytes_sent
        device_traffic[ip]['prev_bytes_recv'] = current_bytes_recv
        device_traffic[ip]['prev_time'] = current_time
        
        # Store last calculated bandwidth
        device_traffic[ip]['last_bandwidth_total'] = bandwidth_total
        device_traffic[ip]['last_bandwidth_sent'] = bandwidth_sent
        device_traffic[ip]['last_bandwidth_recv'] = bandwidth_recv
        
        return max(0, bandwidth_total), max(0, bandwidth_sent), max(0, bandwidth_recv)

def get_network_stats():
    """Get total network statistics"""
    global previous_stats
    
    current_stats = psutil.net_io_counters(pernic=True)
    current_time = time.time()
    
    total_bytes_sent = 0
    total_bytes_recv = 0
    total_bandwidth = 0
    
    with stats_lock:
        for interface, stats in current_stats.items():
            if interface != 'lo' and not interface.startswith('lo'):
                total_bytes_sent += stats.bytes_sent
                total_bytes_recv += stats.bytes_recv
        
        if 'total' in previous_stats:
            time_delta = current_time - previous_stats['total']['time']
            if time_delta > 0:
                sent_per_sec = (total_bytes_sent - previous_stats['total']['bytes_sent']) / time_delta
                recv_per_sec = (total_bytes_recv - previous_stats['total']['bytes_recv']) / time_delta
                total_bandwidth = sent_per_sec + recv_per_sec
        
        previous_stats['total'] = {
            'bytes_sent': total_bytes_sent,
            'bytes_recv': total_bytes_recv,
            'time': current_time
        }
    
    return {
        'total_bytes_sent': total_bytes_sent,
        'total_bytes_recv': total_bytes_recv,
        'total_bandwidth': max(0, total_bandwidth)
    }

def get_connected_devices():
    """Get list of connected devices with REAL traffic data"""
    devices = []
    
    # Discover devices
    active_ips = discover_devices()
    
    # Calculate total bandwidth from all devices
    total_bandwidth_all_devices = 0
    
    with devices_lock:
        for ip in active_ips:
            device_info = discovered_devices.get(ip, {})
            hostname = device_info.get('hostname', f"Device-{ip.split('.')[-1]}")
            mac = device_info.get('mac', 'N/A')
            
            # Get REAL traffic from sniffer
            with sniffer_lock:
                traffic = device_traffic[ip]
                bytes_sent = traffic['bytes_sent']
                bytes_recv = traffic['bytes_recv']
                packets_sent = traffic['packets_sent']
                packets_recv = traffic['packets_recv']
            
            # Calculate REAL bandwidth
            bandwidth_total, bandwidth_sent, bandwidth_recv = calculate_bandwidth_per_device(ip)
            total_bandwidth_all_devices += bandwidth_total
            
            devices.append({
                'ip': ip,
                'mac': mac,
                'hostname': hostname,
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': packets_sent,
                'packets_recv': packets_recv,
                'bandwidth_used': bandwidth_total,
                'bandwidth_sent': bandwidth_sent,
                'bandwidth_recv': bandwidth_recv
            })
    
    return devices, total_bandwidth_all_devices

@app.route('/api/network-stats', methods=['GET'])
def network_stats():
    """API endpoint to get network statistics"""
    try:
        stats = get_network_stats()
        devices, total_device_bandwidth = get_connected_devices()
        
        # Use the MAX between system bandwidth and sum of devices
        total_bandwidth = max(stats['total_bandwidth'], total_device_bandwidth)
        
        return jsonify({
            'total_bandwidth': total_bandwidth,
            'total_bandwidth_system': stats['total_bandwidth'],
            'total_bandwidth_devices': total_device_bandwidth,
            'devices': devices,
            'timestamp': datetime.utcnow().isoformat(),
            'cached_devices': len(discovered_devices),
            'sniffer_active': sniffer_running
        })
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    network_prefix = get_network_prefix()
    interface = get_network_interface()
    
    return jsonify({
        'status': 'ok', 
        'message': 'Network monitor is running',
        'network': f'{network_prefix}.0/24',
        'interface': interface,
        'devices_discovered': len(discovered_devices),
        'sniffer_running': sniffer_running
    })

@app.route('/api/sniffer/start', methods=['POST'])
def start_sniffer():
    """Start packet sniffer"""
    start_packet_sniffer()
    return jsonify({'status': 'started', 'running': sniffer_running})

@app.route('/api/sniffer/stop', methods=['POST'])
def stop_sniffer():
    """Stop packet sniffer"""
    stop_packet_sniffer()
    return jsonify({'status': 'stopped', 'running': sniffer_running})

@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear device cache and traffic stats"""
    global discovered_devices, device_traffic
    
    with devices_lock:
        discovered_devices.clear()
    
    with sniffer_lock:
        device_traffic.clear()
    
    return jsonify({'message': 'Cache cleared', 'status': 'ok'})

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 REAL-TIME NETWORK BANDWIDTH MONITOR")
    print("=" * 70)
    print(f"📡 Local IP: {get_local_ip()}")
    print(f"🌐 Network: {get_network_prefix()}.0/24")
    print(f"🔌 Interface: {get_network_interface()}")
    print()
    
    # Start sniffer
    start_packet_sniffer()
    time.sleep(1)
    
    print("=" * 70)
    print(f"✅ API: http://localhost:5000")
    print(f"📊 Dashboard: http://localhost:3000")
    print("=" * 70)
    
    try:
        app.run(debug=False, host='0.0.0.0', port=5000, threaded=True)
    finally:
        stop_packet_sniffer()