#!/usr/bin/env python3
"""
Network Maximum Bandwidth Calculator
Calculates the theoretical maximum bandwidth of your network interface
"""

import psutil
import socket
import subprocess
import re
import platform
import sys

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

def get_active_interface():
    """Get the active network interface name"""
    try:
        local_ip = get_local_ip()
        
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip:
                    return interface
    except Exception as e:
        print(f"❌ Error: {e}")
    
    return None

def get_interface_speed_linux(interface):
    """Get interface speed on Linux in Mbps"""
    try:
        # Try ethtool first (most accurate)
        result = subprocess.run(
            ['ethtool', interface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Look for "Speed: 1000Mb/s" or similar
            match = re.search(r'Speed:\s*(\d+)Mb/s', result.stdout)
            if match:
                return int(match.group(1))
        
        # Fallback: read from /sys/class/net
        with open(f'/sys/class/net/{interface}/speed', 'r') as f:
            speed = int(f.read().strip())
            return speed if speed > 0 else None
            
    except FileNotFoundError:
        print(f"⚠️  Install ethtool for accurate results: sudo apt install ethtool")
    except Exception:
        pass
    
    return None

def get_interface_speed_windows(interface):
    """Get interface speed on Windows in Mbps"""
    try:
        result = subprocess.run(
            ['powershell', '-Command', 
             f'Get-NetAdapter -Name "{interface}" | Select-Object -ExpandProperty LinkSpeed'],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Output like "1 Gbps" or "100 Mbps"
            output = result.stdout.strip()
            
            if 'Gbps' in output:
                match = re.search(r'(\d+(?:\.\d+)?)\s*Gbps', output)
                if match:
                    return int(float(match.group(1)) * 1000)
            
            if 'Mbps' in output:
                match = re.search(r'(\d+(?:\.\d+)?)\s*Mbps', output)
                if match:
                    return int(float(match.group(1)))
    
    except Exception:
        pass
    
    return None

def get_interface_speed_mac(interface):
    """Get interface speed on macOS in Mbps"""
    try:
        result = subprocess.run(
            ['networksetup', '-getmedia', interface],
            capture_output=True,
            text=True,
            timeout=2
        )
        
        if result.returncode == 0:
            # Look for speed in output
            match = re.search(r'(\d+)(baseT|G)', result.stdout)
            if match:
                speed = int(match.group(1))
                unit = match.group(2)
                
                if unit == 'G':
                    return speed * 1000
                else:
                    return speed
    
    except Exception:
        pass
    
    return None

def get_max_bandwidth(interface):
    """Get maximum theoretical bandwidth for the interface"""
    system = platform.system().lower()
    
    if system == 'linux':
        speed_mbps = get_interface_speed_linux(interface)
    elif system == 'windows':
        speed_mbps = get_interface_speed_windows(interface)
    elif system == 'darwin':  # macOS
        speed_mbps = get_interface_speed_mac(interface)
    else:
        speed_mbps = None
    
    return speed_mbps

def format_speed(mbps):
    """Format speed in human-readable format"""
    if mbps is None:
        return "Unknown"
    
    if mbps >= 1000:
        return f"{mbps / 1000:.1f} Gbps"
    else:
        return f"{mbps} Mbps"

def calculate_max_throughput(mbps):
    """Calculate theoretical maximum throughput in different units"""
    if mbps is None:
        return None
    
    # Convert Mbps to bits per second
    bits_per_sec = mbps * 1_000_000
    
    # Convert to bytes per second (divide by 8)
    bytes_per_sec = bits_per_sec / 8
    
    return {
        'bits_per_sec': bits_per_sec,
        'bytes_per_sec': bytes_per_sec,
        'KB_per_sec': bytes_per_sec / 1024,
        'MB_per_sec': bytes_per_sec / (1024 * 1024),
        'GB_per_sec': bytes_per_sec / (1024 * 1024 * 1024)
    }

def get_interface_stats(interface):
    """Get current interface statistics"""
    try:
        stats = psutil.net_io_counters(pernic=True).get(interface)
        if stats:
            return {
                'bytes_sent': stats.bytes_sent,
                'bytes_recv': stats.bytes_recv,
                'packets_sent': stats.packets_sent,
                'packets_recv': stats.packets_recv,
                'errin': stats.errin,
                'errout': stats.errout,
                'dropin': stats.dropin,
                'dropout': stats.dropout
            }
    except Exception:
        pass
    
    return None

def format_bytes(bytes_val):
    """Format bytes in human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} PB"

def main():
    print("=" * 70)
    print("🌐 NETWORK MAXIMUM BANDWIDTH CALCULATOR")
    print("=" * 70)
    print()
    
    # Get active interface
    interface = get_active_interface()
    local_ip = get_local_ip()
    
    if not interface:
        print("❌ Could not detect active network interface!")
        sys.exit(1)
    
    print(f"📡 Local IP:       {local_ip}")
    print(f"🔌 Interface:      {interface}")
    print()
    
    # Get maximum bandwidth
    max_speed_mbps = get_max_bandwidth(interface)
    
    if max_speed_mbps is None:
        print("⚠️  Could not determine interface speed automatically")
        print("   This might require root/admin privileges")
        print()
        
        if platform.system().lower() == 'linux':
            print("💡 Try: sudo python3 max_bandwidth.py")
            print("   or: sudo apt install ethtool")
        
        sys.exit(1)
    
    print("=" * 70)
    print("📊 MAXIMUM THEORETICAL BANDWIDTH")
    print("=" * 70)
    print()
    print(f"Link Speed:        {format_speed(max_speed_mbps)}")
    print()
    
    # Calculate throughput
    throughput = calculate_max_throughput(max_speed_mbps)
    
    if throughput:
        print("Maximum Throughput (Theoretical):")
        print(f"  • Bits/sec:      {throughput['bits_per_sec']:,.0f} bps")
        print(f"  • Bytes/sec:     {throughput['bytes_per_sec']:,.0f} B/s")
        print(f"  • Kilobytes/sec: {throughput['KB_per_sec']:,.2f} KB/s")
        print(f"  • Megabytes/sec: {throughput['MB_per_sec']:,.2f} MB/s")
        
        if throughput['GB_per_sec'] >= 0.01:
            print(f"  • Gigabytes/sec: {throughput['GB_per_sec']:,.3f} GB/s")
        
        print()
        print(f"Maximum Download:  ~{throughput['MB_per_sec']:,.1f} MB/s")
        print(f"Maximum Upload:    ~{throughput['MB_per_sec']:,.1f} MB/s")
        print()
    
    # Get current stats
    stats = get_interface_stats(interface)
    
    if stats:
        print("=" * 70)
        print("📈 CURRENT INTERFACE STATISTICS")
        print("=" * 70)
        print()
        print(f"Total Sent:        {format_bytes(stats['bytes_sent'])}")
        print(f"Total Received:    {format_bytes(stats['bytes_recv'])}")
        print(f"Packets Sent:      {stats['packets_sent']:,}")
        print(f"Packets Received:  {stats['packets_recv']:,}")
        
        if stats['errin'] > 0 or stats['errout'] > 0:
            print()
            print(f"⚠️  Errors In:      {stats['errin']:,}")
            print(f"⚠️  Errors Out:     {stats['errout']:,}")
        
        if stats['dropin'] > 0 or stats['dropout'] > 0:
            print(f"⚠️  Dropped In:     {stats['dropin']:,}")
            print(f"⚠️  Dropped Out:    {stats['dropout']:,}")
        
        print()
    
    print("=" * 70)
    print("ℹ️  NOTES:")
    print("=" * 70)
    print("• Theoretical maximum assumes:")
    print("  - Perfect conditions (no interference, no errors)")
    print("  - Full duplex operation")
    print("  - No protocol overhead")
    print()
    print("• Real-world speeds are typically 70-95% of theoretical max")
    print("• WiFi speeds vary based on distance, interference, and congestion")
    print("• Check your ISP plan - it may be slower than your network card")
    print("=" * 70)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)