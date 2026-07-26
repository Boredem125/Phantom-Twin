import React, { useState } from 'react';
import { useAlertStream } from './hooks/useAlertStream';
import { SystemHeader } from './components/SystemHeader';
import { AlertQueue } from './components/AlertQueue';
import { PhantomPane } from './components/PhantomPane';
import { EntityHistory } from './components/EntityHistory';
import { InvestigationPanel } from './components/InvestigationPanel';
import type { Alert } from './types/PhantomTwin';
import { Eye, Shield, Cpu, Terminal, ChevronRight } from 'lucide-react';

const App: React.FC = () => {
  const { alerts, status, isConnected } = useAlertStream();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [rightPaneMode, setRightPaneMode] = useState<'default' | 'phantom' | 'history'>('default');
  const [activeEntityId, setActiveEntityId] = useState<string>('');
  const [isPaused, setIsPaused] = useState(false);
  const [frozenAlerts, setFrozenAlerts] = useState<Alert[]>([]);

  // Sync alerts unless user paused the stream
  React.useEffect(() => {
    if (!isPaused) {
      setFrozenAlerts(alerts);
    }
  }, [alerts, isPaused]);

  const handleSelectEntity = (entityId: string) => {
    setActiveEntityId(entityId);
    setRightPaneMode('history');
  };

  const handleSelectPhantom = (entityId: string) => {
    setActiveEntityId(entityId);
    setRightPaneMode('phantom');
  };

  const activeDecoyAlerts = alerts.filter(a => a.phantom_activated);

  return (
    <div className="app-root">
      <SystemHeader status={status} isConnected={isConnected} />

      <main className="main-grid">
        <InvestigationPanel 
          onSelectEntity={handleSelectEntity}
          onSelectAlert={(alert) => {
            setSelectedAlert(alert);
            if (alert && alert.phantom_activated) {
              handleSelectPhantom(alert.entity_id);
            } else {
              handleSelectEntity(alert.entity_id);
            }
          }}
          alerts={alerts}
        />
        {/* Left — Alerts Queue */}
        <div className="left-pane">
          <div className="queue-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div>
              <h2 className="queue-title">
                Intrusion Incident Queue
                <span className="queue-count">{frozenAlerts.length} events</span>
              </h2>
              <p className="queue-subtitle">Real-time behavioral analytics threat stream</p>
            </div>

            {/* Pause/Resume Button */}
            <button 
              onClick={() => setIsPaused(!isPaused)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '6px 12px',
                background: isPaused ? '#EFF6FF' : 'var(--surface)',
                border: '1px solid',
                borderColor: isPaused ? '#BFDBFE' : 'var(--border)',
                color: isPaused ? 'var(--drift)' : 'var(--signal)',
                borderRadius: '8px', fontSize: 11, fontWeight: 600,
                cursor: 'pointer', transition: 'all 0.2s',
                boxShadow: 'var(--shadow-soft)'
              }}
            >
              {isPaused ? (
                <>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--drift)', display: 'inline-block' }} />
                  <span>Resume Stream</span>
                </>
              ) : (
                <>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#EF4444', display: 'inline-block', animation: 'blink 1.2s ease infinite' }} />
                  <span>Pause Stream</span>
                </>
              )}
            </button>
          </div>

          <AlertQueue
            alerts={frozenAlerts}
            onSelectEntity={handleSelectEntity}
            selectedAlert={selectedAlert}
            setSelectedAlert={(alert) => {
              setSelectedAlert(alert);
              if (alert && alert.phantom_activated) {
                handleSelectPhantom(alert.entity_id);
              }
            }}
          />
        </div>

        {/* Right — Detail Pane */}
        <div className="right-pane">
          {rightPaneMode === 'phantom' && activeEntityId && (
            <PhantomPane
              entityId={activeEntityId}
              onClose={() => setRightPaneMode('default')}
            />
          )}

          {rightPaneMode === 'history' && activeEntityId && (
            <EntityHistory
              entityId={activeEntityId}
              onClose={() => setRightPaneMode('default')}
            />
          )}

          {rightPaneMode === 'default' && (
            <div className="right-default">
              {/* Info Banner */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div className="right-shield-icon">
                  <Shield size={20} />
                </div>
                <div>
                  <h3 className="right-title">Active Containment Deception</h3>
                  <p className="right-subtitle">
                    PHANTOM TWIN traps adversaries in synthetic decoy sessions populated
                    dynamically from the compromised target's behavioral history. Click an
                    alert with an active decoy badge to inspect the trapped session feed.
                  </p>
                </div>
              </div>

              {/* Decoy List */}
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <h4 className="decoy-section-title">
                  Active Containment Decoys ({activeDecoyAlerts.length})
                </h4>
                <div className="decoy-list">
                  {activeDecoyAlerts.length === 0 ? (
                    <div className="decoy-empty">
                      <Eye size={20} />
                      <span style={{ fontSize: 11, fontWeight: 600 }}>
                        No active intruder decoys running currently.
                      </span>
                      <span style={{ fontSize: 10 }}>
                        High-risk alerts auto-spawn decoy sessions.
                      </span>
                    </div>
                  ) : (
                    activeDecoyAlerts.map(alert => (
                      <div
                        key={alert.alert_id}
                        className="decoy-item"
                        onClick={() => handleSelectPhantom(alert.entity_id)}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span className="decoy-dot-pulse" />
                          <div>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: 'var(--signal)', display: 'block' }}>
                              {alert.entity_id}
                            </span>
                            <span style={{ fontSize: 10, color: 'var(--muted)' }}>
                              {alert.event.source_ip}
                            </span>
                          </div>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color: 'var(--phantom)' }}>
                          <span>Inspect Decoy</span>
                          <ChevronRight size={12} />
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Info Chips */}
              <div className="info-grid">
                <div className="info-chip">
                  <Cpu size={16} style={{ color: 'var(--drift)', marginTop: 2, flexShrink: 0 }} />
                  <div>
                    <div className="info-chip-title">ICS/OT Devices</div>
                    <div className="info-chip-sub">Decoys emulate PLCs/HMIs dynamically.</div>
                  </div>
                </div>
                <div className="info-chip">
                  <Terminal size={16} style={{ color: 'var(--threat)', marginTop: 2, flexShrink: 0 }} />
                  <div>
                    <div className="info-chip-title">Trapped Command Logging</div>
                    <div className="info-chip-sub">Record every keypress and query safely.</div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

export default App;

