import React, { useCallback, useState, useEffect } from 'react';
import type { PhantomSession, PhantomSummary } from '../types/PhantomTwin';
import { Eye, ShieldAlert, XCircle, Clock, Database, Terminal, Key, Network, X } from 'lucide-react';

interface PhantomPaneProps {
  entityId: string;
  onClose: () => void;
}

const host = '127.0.0.1:8000';
const API_BASE = `http://${host}`;

const spin: React.CSSProperties = {
  width: 24, height: 24,
  borderRadius: '50%',
  border: '2px solid var(--phantom)',
  borderTopColor: 'transparent',
  animation: 'spin 0.8s linear infinite',
  display: 'inline-block',
};

// inject spin keyframe once
if (!document.getElementById('spin-kf')) {
  const s = document.createElement('style');
  s.id = 'spin-kf';
  s.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
  document.head.appendChild(s);
}

export const PhantomPane: React.FC<PhantomPaneProps> = ({ entityId, onClose }) => {
  const [session, setSession] = useState<PhantomSession | null>(null);
  const [summary, setSummary] = useState<PhantomSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isTerminating, setIsTerminating] = useState(false);

  const fetchSessionStatus = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/phantom/${entityId}`);
      if (res.ok) {
        const data = await res.json();
        if (data.status === 'ACTIVE') {
          setSession(data.session);
          setSummary(null);
        } else if (data.status === 'TERMINATED') {
          setSummary(data.summary);
          setSession(null);
        }
      } else {
        setError('No active decoy session found for this endpoint.');
      }
    } catch (err) {
      console.error(err);
      setError('Connection failed. Decoy session unreachable.');
    } finally {
      setLoading(false);
    }
  }, [entityId]);

  useEffect(() => {
    setLoading(true);
    setError(null);
    void fetchSessionStatus();
    const interval = setInterval(() => void fetchSessionStatus(), 3000);
    return () => clearInterval(interval);
  }, [entityId, fetchSessionStatus]);

  const handleTerminate = async () => {
    setIsTerminating(true);
    try {
      const res = await fetch(`${API_BASE}/api/phantom/${entityId}/terminate`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setSummary(data);
        setSession(null);
      }
    } catch (err) {
      console.error('Error terminating session:', err);
    } finally {
      setIsTerminating(false);
    }
  };

  const getActionIcon = (type: string) => {
    const s = { flexShrink: 0 as const };
    if (type === 'AUTH_ATTEMPT')                return <Key size={15} style={{ ...s, color: '#D97706' }} />;
    if (type === 'RESOURCE_PROBE')              return <Database size={15} style={{ ...s, color: '#2563EB' }} />;
    if (type === 'PRIVILEGE_ESCALATION_ATTEMPT')return <ShieldAlert size={15} style={{ ...s, color: '#DC2626' }} />;
    if (type === 'LATERAL_PROBE')               return <Network size={15} style={{ ...s, color: '#7C3AED' }} />;
    return <Terminal size={15} style={{ ...s, color: '#059669' }} />;
  };

  const getActionColor = (type: string): React.CSSProperties => {
    if (type === 'AUTH_ATTEMPT')                return { background: '#FFFBEB', color: '#92400E', border: '1px solid #FDE68A' };
    if (type === 'RESOURCE_PROBE')              return { background: '#EFF6FF', color: '#1E40AF', border: '1px solid #BFDBFE' };
    if (type === 'PRIVILEGE_ESCALATION_ATTEMPT')return { background: '#FEF2F2', color: '#991B1B', border: '1px solid #FECACA' };
    if (type === 'LATERAL_PROBE')               return { background: '#F5F3FF', color: '#5B21B6', border: '1px solid #DDD6FE' };
    return { background: '#F0FDF4', color: '#166534', border: '1px solid #BBF7D0' };
  };

  const formatSeconds = (sec: number) => `${Math.floor(sec / 60)}m ${Math.floor(sec % 60)}s`;

  if (loading) {
    return (
      <div className="panel" style={{ alignItems: 'center', justifyContent: 'center', gap: 12, padding: 40 }}>
        <div style={spin} />
        <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Connecting to decoy session...</span>
      </div>
    );
  }

  if (error || (!session && !summary)) {
    return (
      <div className="panel" style={{ alignItems: 'center', justifyContent: 'center', gap: 16, padding: 40, textAlign: 'center' }}>
        <XCircle size={40} style={{ color: '#FDA4AF' }} />
        <div>
          <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--signal)', marginBottom: 6 }}>No active decoy</h3>
          <p style={{ fontSize: 12, color: 'var(--muted)', maxWidth: 280 }}>{error || 'This entity is not running in deceptive containment.'}</p>
        </div>
        <button className="btn-action" onClick={onClose} style={{ marginTop: 8 }}>Close Panel</button>
      </div>
    );
  }

  return (
    <div className="panel">
      {/* Header — Active */}
      {session && (
        <div className="panel-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ padding: 6, background: 'rgba(217,119,6,0.12)', borderRadius: 8, color: 'var(--phantom)', animation: 'pulse-amber 2s ease infinite' }}>
              <Eye size={16} />
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--signal)' }}>PHANTOM TWIN DECOY</span>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--phantom)', animation: 'blink 1.2s ease infinite', display: 'inline-block' }} />
              </div>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, color: 'var(--phantom)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>
                Session Active — Containment Nominal
              </p>
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--signal)' }}>
              <Clock size={12} style={{ color: 'var(--phantom)' }} />
              {formatSeconds(session.elapsed_seconds)}
            </div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 600, color: 'var(--muted)', background: 'var(--surface)', border: '1px solid var(--border)', padding: '2px 6px', borderRadius: 5, display: 'inline-block', marginTop: 3 }}>
              {session.entity_id}
            </span>
          </div>
        </div>
      )}

      {/* Header — Terminated */}
      {summary && (
        <div className="panel-header" style={{ background: '#F8FAFC' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ padding: 6, background: '#E2E8F0', borderRadius: 8, color: 'var(--muted)' }}>
              <XCircle size={16} />
            </div>
            <div>
              <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--signal)' }}>CONTAINMENT CLOSED</span>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>
                Phantom session terminated
              </p>
            </div>
          </div>
          <button className="panel-close" onClick={onClose}><X size={13} /></button>
        </div>
      )}

      {/* Close for active sessions */}
      {session && (
        <div style={{ position: 'absolute', top: 16, right: 16 }} />
      )}

      {/* Body */}
      <div className="panel-body">

        {/* Session meta */}
        {session && (
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, background: 'var(--void)', border: '1px solid var(--border)', borderRadius: 10, padding: 12, fontSize: 11 }}>
            <div>
              <span style={{ color: 'var(--muted)', fontWeight: 600, display: 'block', marginBottom: 3 }}>Attacker Source IP</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>{session.source_ip}</span>
            </div>
            <div>
              <span style={{ color: 'var(--muted)', fontWeight: 600, display: 'block', marginBottom: 3 }}>Timeout Window</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>{formatSeconds(session.timeout_seconds)}</span>
            </div>
          </div>
        )}

        {/* Live feed */}
        {session && (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
            <div className="detail-label">Attacker Containment Feed ({session.actions.length} actions)</div>
            <div style={{ flex: 1, overflowY: 'auto', border: '1px solid var(--border)', background: 'var(--void)', borderRadius: 10, padding: 10, maxHeight: 400, display: 'flex', flexDirection: 'column', gap: 8 }}>
              {session.actions.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                  <Terminal size={20} style={{ animation: 'blink 1.5s ease infinite' }} />
                  <span style={{ fontSize: 11, fontWeight: 600 }}>Decoy environment initialized. Awaiting attacker commands...</span>
                </div>
              ) : (
                [...session.actions].reverse().map((action, i) => (
                  <div key={i} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 10, padding: '10px 12px', display: 'flex', alignItems: 'flex-start', gap: 10, boxShadow: 'var(--shadow-soft)' }}>
                    <div style={{ padding: 6, background: 'var(--void)', borderRadius: 7, border: '1px solid var(--border)', flexShrink: 0 }}>
                      {getActionIcon(action.action_type)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                        <span style={{ ...getActionColor(action.action_type), padding: '2px 7px', borderRadius: 5, fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.06em', display: 'inline-block' }}>
                          {action.action_type}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)' }}>
                          {new Date(action.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--signal)', background: 'var(--void)', padding: '8px 10px', borderRadius: 7, border: '1px solid var(--border)', overflowX: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>
                        {JSON.stringify(action.details, null, 2)}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Summary */}
        {summary && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14, flex: 1 }}>
            <div className="detail-label">Decoy Session Report</div>
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12, padding: 16, boxShadow: 'var(--shadow-soft)', display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11, borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
                <div>
                  <span style={{ color: 'var(--muted)', fontWeight: 600, display: 'block', marginBottom: 3 }}>Session Duration</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>{formatSeconds(summary.duration_seconds)}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted)', fontWeight: 600, display: 'block', marginBottom: 3 }}>Total Attacker Actions</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>{summary.n_actions} commands trapped</span>
                </div>
              </div>

              <div style={{ borderBottom: '1px solid var(--border)', paddingBottom: 12 }}>
                <div className="detail-label" style={{ marginBottom: 8 }}>Decoy Resources Probed</div>
                {summary.resources_probed.length === 0 ? (
                  <span style={{ fontSize: 11, color: 'var(--muted)', fontStyle: 'italic' }}>No specific resources were probed.</span>
                ) : (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {summary.resources_probed.map((res, i) => (
                      <span key={i} style={{ padding: '3px 8px', background: 'var(--void)', border: '1px solid var(--border)', borderRadius: 6, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--signal)' }}>
                        {res}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <div className="detail-label" style={{ marginBottom: 8 }}>Trapped Vector Statistics</div>
                {Object.entries(summary.action_types).map(([type, count]) => (
                  <div key={type} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, padding: '6px 0', borderBottom: '1px solid rgba(221,225,231,0.4)' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)' }}>{type}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)', background: 'var(--void)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 5 }}>{count as number}</span>
                  </div>
                ))}
              </div>
            </div>
            
            <button 
              className="btn-action" 
              style={{ 
                width: '100%', 
                justifyContent: 'center', 
                background: 'var(--phantom)', 
                color: 'white', 
                border: '1px solid var(--phantom)',
                fontWeight: 700
              }} 
              onClick={() => {
                const dateStr = new Date(summary.terminated_at).toLocaleString();
                const actionLogs = summary.actions && summary.actions.length > 0 
                  ? summary.actions.map(a => `[${new Date(a.timestamp).toLocaleTimeString()}] ${a.action_type}\nDetails: ${JSON.stringify(a.details, null, 2)}`).join('\n\n')
                  : 'No actions recorded.';
                  
                const reportText = `======================================================================
PHANTOM TWIN DECEPTION ENGINE — CONTAINMENT INCIDENT REPORT
======================================================================
Entity ID:            ${summary.entity_id}
Status:               TERMINATED / CONTAINED
Activation Time:      ${new Date(summary.activated_at).toLocaleString()}
Termination Time:      ${dateStr}
Containment Duration: ${formatSeconds(summary.duration_seconds)}
Total Actions Logged: ${summary.n_actions}

----------------------------------------------------------------------
RESOURCES PROBED BY ATTACKER:
----------------------------------------------------------------------
${summary.resources_probed.length > 0 ? summary.resources_probed.map(r => ` - ${r}`).join('\n') : 'No resources probed.'}

----------------------------------------------------------------------
ATTACK VECTOR STATISTICS:
----------------------------------------------------------------------
${Object.entries(summary.action_types).map(([type, count]) => ` - ${type}: ${count}`).join('\n')}

----------------------------------------------------------------------
ATTACKER CONTAINMENT ACTION LOG:
----------------------------------------------------------------------
${actionLogs}

======================================================================
Report generated at ${new Date().toLocaleString()} by PHANTOM TWIN Deception Engine.
======================================================================`;

                const blob = new Blob([reportText], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = `PhantomTwin_Report_${summary.entity_id}.txt`;
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
              }}
            >
              Download Containment Report
            </button>

            <button className="btn-action" style={{ width: '100%', justifyContent: 'center' }} onClick={onClose}>
              Clear Panel & Close
            </button>
          </div>
        )}
      </div>

      {/* Footer — terminate button for active sessions */}
      {session && (
        <div style={{ borderTop: '1px solid var(--border)', background: 'rgba(244,246,249,0.5)', padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600 }}>
            Status: <span style={{ color: 'var(--phantom)', fontWeight: 700, animation: 'blink 1.5s ease infinite' }}>DECOY ACTIVE</span>
          </div>
          <button
            onClick={handleTerminate}
            disabled={isTerminating}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '8px 16px',
              background: '#DC2626', border: '1px solid #B91C1C',
              borderRadius: 10, color: 'white', fontSize: 11, fontWeight: 700,
              cursor: isTerminating ? 'not-allowed' : 'pointer',
              opacity: isTerminating ? 0.6 : 1,
              transition: 'all 0.2s',
              boxShadow: 'var(--shadow-soft)',
            }}
          >
            <XCircle size={13} />
            {isTerminating ? 'Terminating...' : 'Terminate Session'}
          </button>
        </div>
      )}
    </div>
  );
};

