import React, { useState, useEffect, useCallback } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Area, AreaChart } from 'recharts';
import { motion, AnimatePresence } from 'framer-motion';
import './Dashboard.css';

interface Device {
  ip: string;
  mac: string;
  hostname: string;
  bytes_sent: number;
  bytes_recv: number;
  packets_sent: number;
  packets_recv: number;
  bandwidth_used: number;  // SMOOTHED (per legenda e lista)
  bandwidth_used_instant?: number;  // ✅ NUOVO: ISTANTANEO (per il grafico)
  bandwidth_sent: number;
  bandwidth_recv: number;
  is_active?: boolean;
  connection_count?: number;
  first_seen?: number;
}

interface NetworkStats {
  total_bandwidth: number;
  total_bandwidth_system: number;
  total_bandwidth_devices: number;
  devices: Device[];
  timestamp: string;
  sniffer_active?: boolean;
  monitoring_active?: boolean;
  scanner_active?: boolean;
  packets_captured?: number;
  scapy_available?: boolean;
  last_deep_scan?: string;
  next_deep_scan_in?: number;
}

interface ChartDataPoint {
  time: string;
  timestamp: number;
  [key: string]: number | string;
}

const Dashboard: React.FC = () => {
  const [networkStats, setNetworkStats] = useState<NetworkStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [chartData, setChartData] = useState<ChartDataPoint[]>([]);
  const [allDeviceIPs, setAllDeviceIPs] = useState<Set<string>>(new Set());
  const [refreshRate, setRefreshRate] = useState<number>(2000);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  
  // Interactive features
  const [visibleDevices, setVisibleDevices] = useState<Set<string>>(new Set());
  const [hoveredDevice, setHoveredDevice] = useState<string | null>(null);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [showStats, setShowStats] = useState<boolean>(false);
  const [maxBandwidth, setMaxBandwidth] = useState<number>(0);
  
  const MAX_DATA_POINTS = 60;
  
  const DYSTOPIAN_COLORS = [
    '#FF3B30', '#007AFF', '#34C759', '#FF9500', '#AF52DE', '#FF2D55',
    '#5AC8FA', '#FFCC00', '#FF6B6B', '#4ECDC4', '#95E1D3', '#F38181',
  ];

  const REFRESH_RATES = [
    { label: '1s', value: 1000 },
    { label: '2s', value: 2000 },
    { label: '5s', value: 5000 },
    { label: '10s', value: 10000 },
  ];

  const fetchNetworkStats = useCallback(async () => {
    if (isPaused) return;
    
    try {
      const response = await fetch('http://localhost:5000/api/network-stats');
      if (!response.ok) {
        throw new Error('CONNECTION_FAILED');
      }
      const data = await response.json();
      setNetworkStats(data);
      
      const newDataPoint: ChartDataPoint = {
        time: new Date().toLocaleTimeString('en-US', { 
          hour12: false,
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit'
        }),
        timestamp: Date.now()
      };
      
      let currentMaxDeviceBandwidth = 0;
      const newDeviceHostnames = new Set<string>();
      
      data.devices.forEach((device: Device) => {
        // ✅ USA bandwidth_used (SMOOTHED) per il grafico
        // Il backend ora restituisce il valore smoothed in bandwidth_used
        // che è quello che vogliamo tracciare
        newDataPoint[device.hostname] = device.bandwidth_used;
        newDeviceHostnames.add(device.hostname);
        
        // Track max bandwidth usando il valore smoothed
        if (device.bandwidth_used > currentMaxDeviceBandwidth) {
          currentMaxDeviceBandwidth = device.bandwidth_used;
        }
        
        // Auto-add devices with traffic to visible list
        if (device.bandwidth_used > 0) {
          setVisibleDevices(prev => {
            if (!prev.has(device.hostname)) {
              const newSet = new Set(prev);
              newSet.add(device.hostname);
              return newSet;
            }
            return prev;
          });
        }
      });
      
      // Update all device hostnames
      setAllDeviceIPs(newDeviceHostnames);
      
      // Update the overall max bandwidth peak
      setMaxBandwidth(prevMax => Math.max(prevMax, currentMaxDeviceBandwidth));
      
      // Update chart data
      setChartData(prevData => {
        const updatedData = [...prevData, newDataPoint];
        if (updatedData.length > MAX_DATA_POINTS) {
          return updatedData.slice(updatedData.length - MAX_DATA_POINTS);
        }
        return updatedData;
      });
      
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'SYSTEM_ERROR');
    } finally {
      setLoading(false);
    }
  }, [isPaused]);

  useEffect(() => {
    fetchNetworkStats();
    const interval = setInterval(fetchNetworkStats, refreshRate);
    return () => clearInterval(interval);
  }, [refreshRate, isPaused, fetchNetworkStats]);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatBandwidth = (bytesPerSecond: number): string => {
    return formatBytes(bytesPerSecond) + '/s';
  };

  const getSortedDevices = (): Device[] => {
    if (!networkStats) return [];
    // Ordina per bandwidth smoothed decrescente
    return [...networkStats.devices].sort((a, b) => b.bandwidth_used - a.bandwidth_used);
  };

  const getDeviceColor = (hostname: string): string => {
    const deviceNames = Array.from(allDeviceIPs);
    const index = deviceNames.indexOf(hostname);
    return DYSTOPIAN_COLORS[index % DYSTOPIAN_COLORS.length];
  };

  const toggleDeviceVisibility = (hostname: string) => {
    setVisibleDevices(prev => {
      const newSet = new Set(prev);
      if (newSet.has(hostname)) {
        newSet.delete(hostname);
      } else {
        newSet.add(hostname);
      }
      return newSet;
    });
  };

  const showAllDevices = () => {
    setVisibleDevices(new Set(allDeviceIPs));
  };

  const hideAllDevices = () => {
    setVisibleDevices(new Set());
  };

  const openDeviceStats = (device: Device) => {
    setSelectedDevice(device);
    setShowStats(true);
  };

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const sortedPayload = [...payload].sort((a, b) => b.value - a.value);
      
      return (
        <motion.div 
          className="custom-tooltip"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
        >
          <div className="tooltip-header">{label}</div>
          {sortedPayload.map((entry: any, index: number) => (
            <div key={index} className="tooltip-row">
              <span className="tooltip-dot" style={{ backgroundColor: entry.color }}></span>
              <span className="tooltip-label">{entry.name}</span>
              <span className="tooltip-value">{formatBandwidth(entry.value)}</span>
            </div>
          ))}
        </motion.div>
      );
    }
    return null;
  };

  if (loading) {
    return (
      <div className="dashboard">
        <motion.div 
          className="loading-screen"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
        >
          <div className="loading-content">
            <div className="loading-spinner"></div>
            <div className="loading-text">INITIALIZING SYSTEM</div>
            <div className="loading-bar">
              <div className="loading-progress"></div>
            </div>
          </div>
        </motion.div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="dashboard">
        <motion.div 
          className="error-screen"
          initial={{ scale: 0.9, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
        >
          <div className="error-icon">⚠</div>
          <div className="error-title">SYSTEM ERROR</div>
          <div className="error-message">{error}</div>
        </motion.div>
      </div>
    );
  }

  const sortedDevices = getSortedDevices();
  const chartYAxisDomain = [0, maxBandwidth > 1024 ? 'auto' : 1024];

  return (
    <div className="dashboard">
      <motion.header 
        className="dashboard-header"
        initial={{ y: -50, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.5 }}
      >
        <div className="header-content">
          <h1 className="header-title">NETWORK TRAFFIC MONITORING SYSTEM</h1>
          <div className="header-meta">
            <span className={`status-indicator ${isPaused ? 'paused' : ''} ${networkStats?.sniffer_active || networkStats?.monitoring_active || networkStats?.scanner_active ? 'active' : 'inactive'}`}></span>
            <span className="header-timestamp">
              {networkStats?.timestamp ? new Date(networkStats.timestamp).toLocaleString() : 'OFFLINE'}
            </span>
            {networkStats?.packets_captured !== undefined && (
              <span className="header-packets">
                📦 {networkStats.packets_captured.toLocaleString()} packets
              </span>
            )}
            {networkStats?.next_deep_scan_in !== undefined && networkStats.next_deep_scan_in > 0 && (
              <span className="header-scan-timer">
                🔍 Next scan: {Math.floor(networkStats.next_deep_scan_in / 60)}m {networkStats.next_deep_scan_in % 60}s
              </span>
            )}
          </div>
        </div>

        <div className="controls-bar">
          <div className="control-group">
            <span className="control-label">REFRESH RATE:</span>
            <div className="refresh-buttons">
              {REFRESH_RATES.map((rate) => (
                <button
                  key={rate.value}
                  className={`refresh-button ${refreshRate === rate.value ? 'active' : ''}`}
                  onClick={() => setRefreshRate(rate.value)}
                >
                  {rate.label}
                </button>
              ))}
            </div>
          </div>

          <div className="control-group">
            <button
              className="control-button"
              onClick={showAllDevices}
            >
              SHOW ALL
            </button>
            <button
              className="control-button"
              onClick={hideAllDevices}
            >
              HIDE ALL
            </button>
            <button
              className={`pause-button ${isPaused ? 'paused' : ''}`}
              onClick={() => setIsPaused(!isPaused)}
            >
              {isPaused ? '▶ RESUME' : '⏸ PAUSE'}
            </button>
          </div>
        </div>
      </motion.header>

      <div className="metrics-grid">
        {[
          { 
            label: 'TOTAL BANDWIDTH', 
            value: networkStats ? formatBandwidth(networkStats.total_bandwidth) : '0 B/s',
            subtitle: `Devices: ${networkStats ? formatBandwidth(networkStats.total_bandwidth_devices) : '0 B/s'}`,
            color: '#FF3B30',
            icon: '▲'
          },
          { 
            label: 'ACTIVE NODES', 
            value: networkStats?.devices.length || 0,
            subtitle: `Visible: ${visibleDevices.size}`,
            color: '#007AFF',
            icon: '●'
          },
          { 
            label: 'PEAK USAGE', 
            value: formatBandwidth(maxBandwidth),
            subtitle: sortedDevices.length > 0 ? sortedDevices[0].hostname : 'N/A',
            color: '#34C759',
            icon: '▼'
          }
        ].map((metric, index) => (
          <motion.div
            key={index}
            className="metric-card"
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: index * 0.1, duration: 0.4 }}
            whileHover={{ scale: 1.02 }}
          >
            <div className="metric-header">
              <span className="metric-icon" style={{ color: metric.color }}>{metric.icon}</span>
              <span className="metric-label">{metric.label}</span>
            </div>
            <div className="metric-value" style={{ color: metric.color }}>
              {metric.value}
            </div>
            <div className="metric-subtitle">{metric.subtitle}</div>
            <div className="metric-line" style={{ backgroundColor: metric.color }}></div>
          </motion.div>
        ))}
      </div>

      <motion.section 
        className="chart-section"
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3, duration: 0.5 }}
      >
        <div className="section-header">
          <div className="section-title">DATA STREAM ANALYSIS</div>
          <div className="section-meta">
            {visibleDevices.size}/{allDeviceIPs.size} NODES VISIBLE · {refreshRate / 1000}S REFRESH · {chartData.length} DATA POINTS
          </div>
        </div>

        <div className="legend-controls">
          {sortedDevices.map((device, index) => {
            const hostname = device.hostname;
            const isVisible = visibleDevices.has(hostname);
            const isHovered = hoveredDevice === hostname;
            
            return (
              <motion.div
                key={hostname}
                className={`legend-chip ${isVisible ? 'visible' : 'hidden'} ${isHovered ? 'hovered' : ''}`}
                onClick={() => toggleDeviceVisibility(hostname)}
                onMouseEnter={() => setHoveredDevice(hostname)}
                onMouseLeave={() => setHoveredDevice(null)}
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
              >
                <div
                  className="legend-color-dot"
                  style={{ backgroundColor: getDeviceColor(hostname) }}
                ></div>
                <span className="legend-name">{hostname}</span>
                <span className="legend-value">
                  {formatBandwidth(device.bandwidth_used)}
                </span>
              </motion.div>
            );
          })}
        </div>
        
        <div className="chart-container">
          {chartData.length === 0 ? (
            <div style={{ 
              height: '500px', 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'center',
              color: '#666',
              fontSize: '14px'
            }}>
              Waiting for data...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={500}>
              <AreaChart data={chartData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  {Array.from(allDeviceIPs).map((hostname, index) => (
                    <linearGradient key={hostname} id={`gradient-${index}`} x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor={DYSTOPIAN_COLORS[index % DYSTOPIAN_COLORS.length]} stopOpacity={0.3}/>
                      <stop offset="95%" stopColor={DYSTOPIAN_COLORS[index % DYSTOPIAN_COLORS.length]} stopOpacity={0}/>
                    </linearGradient>
                  ))}
                </defs>
                <CartesianGrid strokeDasharray="0" stroke="#2a2a2a" strokeWidth={0.5} />
                <XAxis 
                  dataKey="time" 
                  stroke="#666666" 
                  tick={{ fill: '#999999', fontSize: 11, fontFamily: 'SF Mono, monospace' }}
                  tickLine={false}
                  axisLine={{ stroke: '#333333' }}
                />
                <YAxis 
                  stroke="#666666"
                  tick={{ fill: '#999999', fontSize: 11, fontFamily: 'SF Mono, monospace' }}
                  tickLine={false}
                  axisLine={{ stroke: '#333333' }}
                  tickFormatter={(value) => formatBandwidth(value)}
                  domain={chartYAxisDomain}
                  allowDataOverflow={true}
                />
                <Tooltip content={<CustomTooltip />} />
                <Legend 
                  wrapperStyle={{ display: 'none' }}
                />
                {Array.from(allDeviceIPs).map((hostname, index) => {
                  const isVisible = visibleDevices.has(hostname);
                  const isHovered = hoveredDevice === hostname;
                  
                  return (
                    <Area
                      key={hostname}
                      type="monotone"
                      dataKey={hostname}
                      stroke={DYSTOPIAN_COLORS[index % DYSTOPIAN_COLORS.length]}
                      strokeWidth={isHovered ? 4 : isVisible ? 2 : 0}
                      fill={isVisible ? `url(#gradient-${index})` : 'none'}
                      dot={false}
                      activeDot={{ r: 6, fill: DYSTOPIAN_COLORS[index % DYSTOPIAN_COLORS.length], stroke: '#000', strokeWidth: 2 }}
                      opacity={isVisible ? (isHovered ? 1 : 0.8) : 0}
                    />
                  );
                })}
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </motion.section>

      <motion.section 
        className="ranking-section"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.5, duration: 0.5 }}
      >
        <div className="section-header">
          <div className="section-title">RESOURCE ALLOCATION</div>
          <div className="section-meta">SORTED BY BANDWIDTH CONSUMPTION (HIGH → LOW)</div>
        </div>

        {sortedDevices.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">○</div>
            <div className="empty-text">NO ACTIVE CONNECTIONS</div>
          </div>
        ) : (
          <div className="device-list">
            {sortedDevices.map((device, index) => (
              <motion.div
                key={device.ip}
                className="device-item"
                initial={{ x: -30, opacity: 0 }}
                animate={{ x: 0, opacity: 1 }}
                transition={{ delay: index * 0.03, duration: 0.3 }}
                whileHover={{ x: 5, borderColor: getDeviceColor(device.hostname) }}
                onClick={() => openDeviceStats(device)}
                onMouseEnter={() => setHoveredDevice(device.hostname)}
                onMouseLeave={() => setHoveredDevice(null)}
              >
                <div className="device-rank">
                  <div className="rank-number">{String(index + 1).padStart(2, '0')}</div>
                </div>

                <div 
                  className="device-indicator"
                  style={{ backgroundColor: getDeviceColor(device.hostname) }}
                ></div>

                <div className="device-info">
                  <div className="device-name">{device.hostname}</div>
                  <div className="device-meta">
                    <span className="device-detail">{device.ip}</span>
                    <span className="device-separator">·</span>
                    <span className="device-detail">{device.mac}</span>
                    {device.connection_count !== undefined && device.connection_count > 0 && (
                      <>
                        <span className="device-separator">·</span>
                        <span className="device-detail">{device.connection_count} conn</span>
                      </>
                    )}
                  </div>
                </div>

                <div className="device-metrics">
                  <div className="metric-item">
                    <div className="metric-item-label">CURRENT</div>
                    <div className="metric-item-value" style={{ color: getDeviceColor(device.hostname) }}>
                      {formatBandwidth(device.bandwidth_used)}
                    </div>
                  </div>
                  <div className="metric-item">
                    <div className="metric-item-label">TX</div>
                    <div className="metric-item-value">{formatBytes(device.bytes_sent)}</div>
                  </div>
                  <div className="metric-item">
                    <div className="metric-item-label">RX</div>
                    <div className="metric-item-value">{formatBytes(device.bytes_recv)}</div>
                  </div>
                </div>

                <div className="device-progress">
                  <div
                    className="device-progress-bar"
                    style={{
                      width: `${sortedDevices[0].bandwidth_used > 0 
                        ? (device.bandwidth_used / sortedDevices[0].bandwidth_used) * 100
                        : 0}%`,
                      backgroundColor: getDeviceColor(device.hostname)
                    }}
                  ></div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </motion.section>

      {/* Device Stats Modal */}
      <AnimatePresence>
        {showStats && selectedDevice && (
          <motion.div
            className="modal-overlay"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowStats(false)}
          >
            <motion.div
              className="modal-content"
              initial={{ scale: 0.9, y: 50 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 50 }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="modal-header">
                <h2>{selectedDevice.hostname}</h2>
                <button className="modal-close" onClick={() => setShowStats(false)}>✕</button>
              </div>
              
              <div className="modal-body">
                <div className="stats-grid">
                  <div className="stat-box">
                    <div className="stat-label">IP Address</div>
                    <div className="stat-value">{selectedDevice.ip}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">MAC Address</div>
                    <div className="stat-value">{selectedDevice.mac}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Total Bandwidth</div>
                    <div className="stat-value">{formatBandwidth(selectedDevice.bandwidth_used)}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Upload Speed</div>
                    <div className="stat-value">{formatBandwidth(selectedDevice.bandwidth_sent)}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Download Speed</div>
                    <div className="stat-value">{formatBandwidth(selectedDevice.bandwidth_recv)}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Packets Sent</div>
                    <div className="stat-value">{selectedDevice.packets_sent.toLocaleString()}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Packets Received</div>
                    <div className="stat-value">{selectedDevice.packets_recv.toLocaleString()}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Total Data Sent</div>
                    <div className="stat-value">{formatBytes(selectedDevice.bytes_sent)}</div>
                  </div>
                  <div className="stat-box">
                    <div className="stat-label">Total Data Received</div>
                    <div className="stat-value">{formatBytes(selectedDevice.bytes_recv)}</div>
                  </div>
                  {selectedDevice.connection_count !== undefined && (
                    <div className="stat-box">
                      <div className="stat-label">Active Connections</div>
                      <div className="stat-value">{selectedDevice.connection_count}</div>
                    </div>
                  )}
                  {selectedDevice.first_seen !== undefined && selectedDevice.first_seen > 0 && (
                    <div className="stat-box">
                      <div className="stat-label">First Seen</div>
                      <div className="stat-value">
                        {new Date(selectedDevice.first_seen * 1000).toLocaleString()}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Dashboard;