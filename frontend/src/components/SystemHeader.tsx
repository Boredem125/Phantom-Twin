import React from 'react';
import { Shield, Activity, AlertOctagon, Users, Eye } from 'lucide-react';
import type { SystemStatus } from '../types/PhantomTwin';

interface SystemHeaderProps {
  status: SystemStatus;
  isConnected: boolean;
}

export const SystemHeader: React.FC<SystemHeaderProps> = ({ status, isConnected }) => {
  const healthClass = status.health === 'NOMINAL' ? 'nominal' : status.health === 'DEGRADED' ? 'degraded' : 'offline';

  return (
    <header className="sys-header">
      <div className="sys-header-inner">

        {/* Brand */}
        <div className="brand">
          <div className="brand-icon">
            <Shield size={18} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="brand-name">PHANTOM TWIN</span>
              <span className="brand-version">v1.0.0</span>
            </div>
            <span className="brand-sub">Behavioral Intrusion Deception Engine</span>
          </div>
        </div>

        {/* Stats Row */}
        <div className="stat-row">
          <div className="stat-chip">
            <div className="stat-chip-icon blue">
              <Activity size={15} />
            </div>
            <div>
              <div className="stat-label">Events</div>
              <div className="stat-value">{status.total_events_processed.toLocaleString()}</div>
            </div>
          </div>

          <div className="stat-chip">
            <div className="stat-chip-icon red">
              <AlertOctagon size={15} />
            </div>
            <div>
              <div className="stat-label">Alerts</div>
              <div className="stat-value">{status.total_alerts}</div>
            </div>
          </div>

          <div className="stat-chip">
            <div className="stat-chip-icon amber" style={{ position: 'relative' }}>
              <Eye size={15} />
              {status.active_phantom_sessions > 0 && (
                <span style={{
                  position: 'absolute', top: 3, right: 3,
                  width: 6, height: 6, background: 'var(--phantom)',
                  borderRadius: '50%', animation: 'blink 1.2s ease infinite'
                }} />
              )}
            </div>
            <div>
              <div className="stat-label">Decoys</div>
              <div className="stat-value" style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                {status.active_phantom_sessions}
                {status.active_phantom_sessions > 0 && (
                  <span style={{ width: 7, height: 7, background: 'var(--phantom)', borderRadius: '50%', animation: 'blink 1s ease infinite' }} />
                )}
              </div>
            </div>
          </div>

          <div className="stat-chip">
            <div className="stat-chip-icon slate">
              <Users size={15} />
            </div>
            <div>
              <div className="stat-label">Entities</div>
              <div className="stat-value">{status.entities_monitored}</div>
            </div>
          </div>
        </div>

        {/* Status */}
        <div className="status-row">
          <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Stream:</span>
          <span className={`stream-badge ${isConnected ? 'live' : 'dead'}`}>
            <span className={`stream-dot ${isConnected ? 'live' : 'dead'}`} />
            {isConnected ? 'LIVE' : 'OFFLINE'}
          </span>

          <span className="status-divider">|</span>

          <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Health:</span>
          <span className={`health-badge ${healthClass}`}>
            <span className={`health-dot ${healthClass}`} />
            {status.health}
          </span>
        </div>
      </div>
    </header>
  );
};
