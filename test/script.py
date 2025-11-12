#!/usr/bin/env python3
"""
LAN Traffic Generator
Generates massive traffic INSIDE your local network to test monitoring
"""

import socket
import threading
import time
import random
import struct
import sys
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

TARGET_IP = "192.168.1.100"  # ✅ CAMBIA CON IP DEL PC CHE MONITORA
TARGET_PORT = 9999           # Porta per traffico TCP
UDP_PORT = 9998              # Porta per traffico UDP

NUM_TCP_THREADS = 10         # Thread TCP
NUM_UDP_THREADS = 10         # Thread UDP
PACKET_SIZE = 1024 * 64      # 64KB per packet
PACKETS_PER_SECOND = 100     # Velocità invio

# ============================================================================
# TCP TRAFFIC GENERATOR
# ============================================================================

class TCPTrafficGenerator:
    def __init__(self, target_ip, target_port, thread_id):
        self.target_ip = target_ip
        self.target_port = target_port
        self.thread_id = thread_id
        self.running = True
        self.bytes_sent = 0
        self.packets_sent = 0
    
    def generate_traffic(self):
        """Genera traffico TCP continuo"""
        while self.running:
            try:
                # Crea connessione TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                
                try:
                    sock.connect((self.target_ip, self.target_port))
                    print(f"✅ [TCP-{self.thread_id:02d}] Connected to {self.target_ip}:{self.target_port}")
                except ConnectionRefusedError:
                    # Normale se nessuno ascolta, continua a inviare
                    pass
                
                # Invia pacchetti
                for _ in range(PACKETS_PER_SECOND):
                    if not self.running:
                        break
                    
                    # Genera dati casuali
                    data = random.randbytes(PACKET_SIZE)
                    
                    try:
                        sock.sendall(data)
                        self.bytes_sent += len(data)
                        self.packets_sent += 1
                    except:
                        break
                    
                    time.sleep(1.0 / PACKETS_PER_SECOND)
                
                sock.close()
                
            except Exception as e:
                print(f"⚠️  [TCP-{self.thread_id:02d}] Error: {e}")
                time.sleep(1)
    
    def start(self):
        """Avvia thread"""
        thread = threading.Thread(target=self.generate_traffic, daemon=True)
        thread.start()
        return thread

# ============================================================================
# UDP TRAFFIC GENERATOR
# ============================================================================

class UDPTrafficGenerator:
    def __init__(self, target_ip, target_port, thread_id):
        self.target_ip = target_ip
        self.target_port = target_port
        self.thread_id = thread_id
        self.running = True
        self.bytes_sent = 0
        self.packets_sent = 0
    
    def generate_traffic(self):
        """Genera traffico UDP continuo"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        print(f"✅ [UDP-{self.thread_id:02d}] Sending to {self.target_ip}:{self.target_port}")
        
        while self.running:
            try:
                # Genera dati casuali
                data = random.randbytes(PACKET_SIZE)
                
                # Invia UDP packet
                sock.sendto(data, (self.target_ip, self.target_port))
                
                self.bytes_sent += len(data)
                self.packets_sent += 1
                
                time.sleep(1.0 / PACKETS_PER_SECOND)
                
            except Exception as e:
                print(f"⚠️  [UDP-{self.thread_id:02d}] Error: {e}")
                time.sleep(1)
        
        sock.close()
    
    def start(self):
        """Avvia thread"""
        thread = threading.Thread(target=self.generate_traffic, daemon=True)
        thread.start()
        return thread

# ============================================================================
# HTTP TRAFFIC GENERATOR (LAN)
# ============================================================================

class HTTPTrafficGenerator:
    def __init__(self, target_ip, thread_id):
        self.target_ip = target_ip
        self.thread_id = thread_id
        self.running = True
        self.requests_sent = 0
    
    def generate_traffic(self):
        """Genera richieste HTTP verso IP nella LAN"""
        while self.running:
            try:
                # Prova a connettersi su porte comuni
                ports = [80, 8080, 5000, 3000, 5173, 8000]
                port = random.choice(ports)
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                try:
                    sock.connect((self.target_ip, port))
                    
                    # Invia richiesta HTTP
                    request = f"GET / HTTP/1.1\r\nHost: {self.target_ip}\r\n\r\n"
                    sock.sendall(request.encode())
                    
                    # Ricevi risposta (crea traffico bidirezionale)
                    try:
                        data = sock.recv(4096)
                        self.requests_sent += 1
                        print(f"✅ [HTTP-{self.thread_id:02d}] Request to {self.target_ip}:{port} - {len(data)} bytes received")
                    except:
                        pass
                    
                except:
                    # Porta chiusa, continua
                    pass
                finally:
                    sock.close()
                
                time.sleep(0.5)
                
            except Exception as e:
                time.sleep(1)
    
    def start(self):
        """Avvia thread"""
        thread = threading.Thread(target=self.generate_traffic, daemon=True)
        thread.start()
        return thread

# ============================================================================
# PING GENERATOR (ICMP)
# ============================================================================

class PingGenerator:
    def __init__(self, target_ip, thread_id):
        self.target_ip = target_ip
        self.thread_id = thread_id
        self.running = True
    
    def generate_traffic(self):
        """Genera ping continui"""
        import subprocess
        import platform
        
        system = platform.system().lower()
        
        while self.running:
            try:
                if system == 'windows':
                    # Windows: ping -n 1
                    result = subprocess.run(
                        ['ping', '-n', '1', self.target_ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )
                else:
                    # Linux: ping -c 1
                    result = subprocess.run(
                        ['ping', '-c', '1', self.target_ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )
                
                if result.returncode == 0:
                    print(f"✅ [PING-{self.thread_id:02d}] Ping to {self.target_ip} successful")
                
                time.sleep(0.1)  # Ping veloce
                
            except Exception as e:
                time.sleep(1)
    
    def start(self):
        """Avvia thread"""
        thread = threading.Thread(target=self.generate_traffic, daemon=True)
        thread.start()
        return thread

# ============================================================================
# STATISTICS MONITOR
# ============================================================================

class StatsMonitor:
    def __init__(self, generators):
        self.generators = generators
        self.running = True
        self.start_time = time.time()
    
    def monitor(self):
        """Monitora statistiche"""
        while self.running:
            time.sleep(5)
            
            total_bytes = 0
            total_packets = 0
            total_requests = 0
            
            for gen in self.generators:
                if hasattr(gen, 'bytes_sent'):
                    total_bytes += gen.bytes_sent
                if hasattr(gen, 'packets_sent'):
                    total_packets += gen.packets_sent
                if hasattr(gen, 'requests_sent'):
                    total_requests += gen.requests_sent
            
            elapsed = time.time() - self.start_time
            bandwidth = (total_bytes / elapsed) / (1024 * 1024)  # MB/s
            
            print("\n" + "=" * 70)
            print(f"📊 STATISTICS [{datetime.now().strftime('%H:%M:%S')}]")
            print("=" * 70)
            print(f"   Running time:     {int(elapsed)}s")
            print(f"   Total sent:       {total_bytes / (1024*1024):.2f} MB")
            print(f"   Total packets:    {total_packets}")
            print(f"   HTTP requests:    {total_requests}")
            print(f"   Average speed:    {bandwidth:.2f} MB/s")
            print("=" * 70 + "\n")
    
    def start(self):
        """Avvia thread"""
        thread = threading.Thread(target=self.monitor, daemon=True)
        thread.start()
        return thread

# ============================================================================
# MAIN
# ============================================================================

def print_banner():
    """Stampa banner"""
    print("\n" + "=" * 70)
    print("  🔥 LAN TRAFFIC GENERATOR 🔥".center(70))
    print("=" * 70)
    print()

def get_local_ip():
    """Ottiene IP locale"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "Unknown"

def main():
    print_banner()
    
    local_ip = get_local_ip()
    
    print(f"⚙️  Configuration:")
    print(f"   Source IP:        {local_ip}")
    print(f"   Target IP:        {TARGET_IP}")
    print(f"   TCP Port:         {TARGET_PORT}")
    print(f"   UDP Port:         {UDP_PORT}")
    print(f"   TCP Threads:      {NUM_TCP_THREADS}")
    print(f"   UDP Threads:      {NUM_UDP_THREADS}")
    print(f"   Packet size:      {PACKET_SIZE / 1024:.0f} KB")
    print(f"   Packets/sec:      {PACKETS_PER_SECOND}")
    print()
    print(f"💡 Dashboard: http://{TARGET_IP}:5173")
    print()
    print("⚠️  This device will generate MASSIVE traffic to target!")
    print("=" * 70 + "\n")
    
    try:
        input("Press ENTER to start or Ctrl+C to cancel...")
    except KeyboardInterrupt:
        print("\nCancelled!")
        return
    
    print("\n🚀 Starting traffic generation...\n")
    
    generators = []
    threads = []
    
    try:
        # Start TCP generators
        for i in range(NUM_TCP_THREADS):
            gen = TCPTrafficGenerator(TARGET_IP, TARGET_PORT, i)
            generators.append(gen)
            threads.append(gen.start())
        print(f"✅ Started {NUM_TCP_THREADS} TCP threads")
        
        # Start UDP generators
        for i in range(NUM_UDP_THREADS):
            gen = UDPTrafficGenerator(TARGET_IP, UDP_PORT, i)
            generators.append(gen)
            threads.append(gen.start())
        print(f"✅ Started {NUM_UDP_THREADS} UDP threads")
        
        # Start HTTP generators
        for i in range(5):
            gen = HTTPTrafficGenerator(TARGET_IP, i)
            generators.append(gen)
            threads.append(gen.start())
        print(f"✅ Started 5 HTTP threads")
        
        # Start Ping generators
        for i in range(3):
            gen = PingGenerator(TARGET_IP, i)
            threads.append(gen.start())
        print(f"✅ Started 3 PING threads")
        
        # Start stats monitor
        monitor = StatsMonitor(generators)
        threads.append(monitor.start())
        
        print("\n" + "=" * 70)
        print("💡 Check your dashboard to see THIS device traffic spike!")
        print("=" * 70)
        print("Press Ctrl+C to stop...\n")
        
        # Keep running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping all traffic generators...")
        
        # Stop generators
        for gen in generators:
            gen.running = False
        
        if 'monitor' in locals():
            monitor.running = False
        
        time.sleep(2)
        print("✅ All traffic stopped!")
        
        # Final stats
        total_bytes = sum(gen.bytes_sent for gen in generators if hasattr(gen, 'bytes_sent'))
        print(f"\n📊 Total data sent: {total_bytes / (1024*1024):.2f} MB")

if __name__ == '__main__':
    main()