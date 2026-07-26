import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert, SystemStatus } from '../types/PhantomTwin';

const host = '127.0.0.1:8000';
const API_BASE = `http://${host}`;
const WS_URL = `ws://${host}/ws/alerts`;

export function useAlertStream() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<SystemStatus>({
    total_events_processed: 0,
    total_alerts: 0,
    active_phantom_sessions: 0,
    entities_monitored: 0,
    health: 'OFFLINE'
  });
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  // Fetch initial alerts and status
  const fetchInitialData = useCallback(async () => {
    try {
      // Fetch status
      const statusRes = await fetch(`${API_BASE}/api/status`);
      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setStatus(prev => ({ ...prev, ...statusData, health: 'NOMINAL' }));
      }

      // Fetch alerts
      const alertsRes = await fetch(`${API_BASE}/api/alerts?n=100`);
      if (alertsRes.ok) {
        const alertsData = await alertsRes.json();
        setAlerts(alertsData);
      }
    } catch (err) {
      console.error('Error fetching initial data:', err);
      setStatus(prev => ({ ...prev, health: 'DEGRADED' }));
    }
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const statusRes = await fetch(`${API_BASE}/api/status`);
      if (statusRes.ok) {
        const statusData = await statusRes.json();
        setStatus(prev => ({ ...prev, ...statusData }));
      }
    } catch (err) {
      console.error('Error fetching status:', err);
    }
  }, []);

  // Connect to websocket
  const connect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
    }

    console.log('Connecting to WebSocket alert stream...');
    const ws = new WebSocket(WS_URL);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('WebSocket connected.');
      setIsConnected(true);
      fetchInitialData();
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        
        // Skip ping messages
        if (data.type === 'ping') return;

        // If it's a valid alert, add to list and update counters
        if (data.alert_id) {
          setAlerts(prev => {
            // Check if alert already exists to prevent duplicates
            const exists = prev.some(a => a.alert_id === data.alert_id);
            if (exists) return prev;
            return [data, ...prev].slice(0, 200); // cap at 200 in UI
          });
          
          // Trigger a quick status update to sync counters
          fetchStatus();
        }
      } catch (err) {
        console.error('Error parsing WebSocket message:', err);
      }
    };

    ws.onclose = () => {
      console.log('WebSocket disconnected. Reconnecting in 3 seconds...');
      setIsConnected(false);
      setStatus(prev => ({ ...prev, health: 'OFFLINE' }));
      
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    };

    ws.onerror = (err) => {
      console.error('WebSocket error:', err);
      ws.close();
    };
  }, [fetchInitialData, fetchStatus]);

  useEffect(() => {
    connect();

    // Poll status periodically (every 10s) just in case
    const statusInterval = setInterval(fetchStatus, 10000);

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      clearInterval(statusInterval);
    };
  }, [connect, fetchStatus]);

  // Manually update alert list (e.g. when updating a phantom session status locally)
  const updateAlertLocally = useCallback((updatedAlert: Alert) => {
    setAlerts(prev => prev.map(a => a.alert_id === updatedAlert.alert_id ? updatedAlert : a));
  }, []);

  return {
    alerts,
    status,
    isConnected,
    refetchStatus: fetchStatus,
    updateAlertLocally
  };
}
