import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';

// Connect to the backend
const socket = io('http://localhost:3000');

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ total: 0, highThreat: 0, topTechnique: 'None' });

  useEffect(() => {
    // Fetch historical alerts on load
    fetch('http://localhost:3000/api/alerts')
      .then(res => res.json())
      .then(data => {
        if (data.alerts) {
          setAlerts(data.alerts);
          calculateStats(data.alerts);
        }
      })
      .catch(err => console.error("Failed to fetch history:", err));

    // Listen for live attacks
    socket.on('alert', (newAlert) => {
      setAlerts(prev => {
        const updated = [newAlert, ...prev];
        calculateStats(updated);
        return updated;
      });
    });

    return () => socket.off('alert');
  }, []);

  const calculateStats = (data) => {
    const highThreat = data.filter(a => a.threat_score > 0.6).length;
    
    // Find most common MITRE technique
    const techniques = data.flatMap(a => a.mitre?.techniques?.map(t => t.techniqueId) || []);
    const top = techniques.sort((a,b) =>
          techniques.filter(v => v===a).length - techniques.filter(v => v===b).length
    ).pop() || 'None';

    setStats({ total: data.length, highThreat, topTechnique: top });
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'monospace', backgroundColor: '#0f172a', color: '#e2e8f0', minHeight: '100vh' }}>
      <h1 style={{ borderBottom: '2px solid #334155', paddingBottom: '10px', color: '#38bdf8' }}>
        🛡️ ShadowNet SOC | Live Telemetry
      </h1>
      
      <div style={{ display: 'flex', gap: '20px', marginBottom: '30px' }}>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '8px', flex: 1, borderTop: '4px solid #38bdf8' }}>
          <h3>Total Attacks Caught</h3>
          <p style={{ fontSize: '2em', margin: 0, color: '#f8fafc' }}>{stats.total}</p>
        </div>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '8px', flex: 1, borderTop: '4px solid #ef4444' }}>
          <h3>High Confidence Threats (ML)</h3>
          <p style={{ fontSize: '2em', margin: 0, color: '#f8fafc' }}>{stats.highThreat}</p>
        </div>
        <div style={{ background: '#1e293b', padding: '20px', borderRadius: '8px', flex: 1, borderTop: '4px solid #f59e0b' }}>
          <h3>Top MITRE Technique</h3>
          <p style={{ fontSize: '2em', margin: 0, color: '#f8fafc' }}>{stats.topTechnique}</p>
        </div>
      </div>

      <h2 style={{ color: '#94a3b8' }}>Live Attack Feed</h2>
      <table style={{ width: '100%', textAlign: 'left', borderCollapse: 'collapse', background: '#1e293b' }}>
        <thead>
          <tr style={{ background: '#334155' }}>
            <th style={{ padding: '12px' }}>Timestamp</th>
            <th style={{ padding: '12px' }}>Sensor</th>
            <th style={{ padding: '12px' }}>Attacker IP</th>
            <th style={{ padding: '12px' }}>ML Score</th>
            <th style={{ padding: '12px' }}>MITRE Framework</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, i) => (
            <tr key={i} style={{ borderBottom: '1px solid #334155' }}>
              <td style={{ padding: '12px' }}>{new Date(alert.timestamp).toLocaleTimeString()}</td>
              <td style={{ padding: '12px', color: '#f472b6' }}>{alert.sensor.toUpperCase()}</td>
              <td style={{ padding: '12px', color: '#34d399' }}>{alert.sourceIp}</td>
              <td style={{ padding: '12px' }}>
                <span style={{ color: alert.threat_score > 0.6 ? '#ef4444' : '#fbbf24' }}>
                  {(alert.threat_score * 100).toFixed(1)}%
                </span>
              </td>
              <td style={{ padding: '12px', color: '#60a5fa' }}>
                {alert.mitre?.techniques?.map(t => `${t.techniqueId}: ${t.techniqueName}`).join(', ') || 'N/A'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}