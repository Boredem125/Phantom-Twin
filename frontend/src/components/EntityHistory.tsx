import React, { useState, useEffect } from 'react';
import { Info, Clock, AlertTriangle, User, Cpu, Server, MapPin, X } from 'lucide-react';
import type { Alert, Event } from '../types/PhantomTwin';

interface EntityHistoryProps {
  entityId: string;
  onClose: () => void;
}

const host = '127.0.0.1:8000';
const API_BASE = `http://${host}`;

const spin: React.CSSProperties = {
  width: 24, height: 24,
  borderRadius: '50%',
  border: '2px solid var(--drift)',
  borderTopColor: 'transparent',
  animation: 'spin 0.8s linear infinite',
  display: 'inline-block',
};

export const EntityHistory: React.FC<EntityHistoryProps> = ({ entityId, onClose }) => {
  const [profile, setProfile] = useState<any>(null);
  const [events, setEvents] = useState<Event[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchEntityData = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch(`${API_BASE}/api/entity/${entityId}`);
        if (res.ok) {
          const data = await res.json();
          setProfile(data.profile);
          setEvents(data.recent_events || []);
          setAlerts(data.recent_alerts || []);
        } else {
          setError('Failed to fetch details for this entity.');
        }
      } catch (err) {
        console.error(err);
        setError('Server connection failed. Could not fetch timeline.');
      } finally {
        setLoading(false);
      }
    };
    fetchEntityData();
  }, [entityId]);

  const getEntityIcon = (type: string) => {
    if (type === 'service_account') return <Server size={16} style={{ color: 'var(--muted)' }} />;
    if (type === 'edge_device')     return <Cpu size={16} style={{ color: 'var(--muted)' }} />;
    return <User size={16} style={{ color: 'var(--muted)' }} />;
  };

  const formatHour = (h: number) => {
    const hours = Math.floor(h);
    const mins = Math.floor((h - hours) * 60);
    const ampm = hours >= 12 ? 'PM' : 'AM';
    return `${hours % 12 || 12}:${mins.toString().padStart(2, '0')} ${ampm}`;
  };

  if (loading) {
    return (
      <div className="panel" style={{ alignItems: 'center', justifyContent: 'center', gap: 12, padding: 40 }}>
        <div style={spin} />
        <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 500 }}>Retrieving profile timeline...</span>
      </div>
    );
  }

  if (error || !profile) {
    return (
      <div className="panel" style={{ alignItems: 'center', justifyContent: 'center', gap: 16, padding: 40, textAlign: 'center' }}>
        <AlertTriangle size={40} style={{ color: '#FDA4AF' }} />
        <div>
          <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--signal)', marginBottom: 6 }}>Profile unavailable</h3>
          <p style={{ fontSize: 12, color: 'var(--muted)', maxWidth: 280 }}>{error || 'This entity profile has not yet been serialized.'}</p>
        </div>
        <button className="btn-action" onClick={onClose} style={{ marginTop: 8 }}>Close Panel</button>
      </div>
    );
  }

  return (
    <div className="panel">
      {/* Header */}
      <div className="panel-header" style={{ background: 'var(--void)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ padding: 6, background: 'var(--void)', border: '1px solid var(--border)', borderRadius: 8, color: 'var(--signal)' }}>
            {getEntityIcon(profile.entity_type)}
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 700, color: 'var(--signal)' }}>{profile.entity_id}</span>
              {profile.bootstrap && (
                <span style={{ padding: '1px 6px', background: '#EFF6FF', border: '1px solid #BFDBFE', color: 'var(--drift)', fontSize: 9, fontWeight: 700, fontFamily: 'var(--font-mono)', letterSpacing: '0.08em', textTransform: 'uppercase', borderRadius: 5, display: 'inline-block' }}>
                  BOOTSTRAP
                </span>
              )}
            </div>
            <p style={{ fontFamily: 'var(--font-mono)', fontSize: 9, fontWeight: 700, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 2 }}>
              Entity Baseline Profile
            </p>
          </div>
        </div>
        <button className="panel-close" onClick={onClose}><X size={13} /></button>
      </div>

      {/* Body */}
      <div className="panel-body">

        {/* Behavioral Baseline */}
        <div style={{ background: 'var(--void)', border: '1px solid var(--border)', borderRadius: 12, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="detail-label">Behavioral Baseline</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 11 }}>
            {[
              { label: 'Typical Login Hours', value: `${formatHour(profile.peak_hour)} (±${profile.hour_sigma.toFixed(1)}h)` },
              { label: 'Auth Method', value: profile.preferred_auth?.toUpperCase() },
              { label: 'Session Duration', value: `${profile.avg_duration?.toFixed(0)} min (±${profile.dur_sigma?.toFixed(0)}m)` },
              { label: 'Profile Status', value: profile.bootstrap ? 'Synthetic (Bootstrap)' : `Trained (${profile.n_events} events)` },
            ].map(({ label, value }) => (
              <div key={label} style={{ background: 'var(--surface)', border: '1px solid rgba(221,225,231,0.6)', borderRadius: 8, padding: '8px 10px' }}>
                <span style={{ color: 'var(--muted)', fontWeight: 600, display: 'block', marginBottom: 3 }}>{label}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--signal)' }}>{value}</span>
              </div>
            ))}
          </div>

          {/* Geos & Fingerprints */}
          <div style={{ borderTop: '1px solid rgba(221,225,231,0.6)', paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--muted)', display: 'block', marginBottom: 5 }}>Approved Geographies</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {(profile.home_geos || []).map((geo: string) => (
                  <span key={geo} style={{ display: 'inline-flex', alignItems: 'center', gap: 3, padding: '2px 7px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 5, fontSize: 10, color: 'var(--signal)', fontWeight: 500 }}>
                    <MapPin size={10} style={{ color: 'var(--muted)' }} />
                    {geo}
                  </span>
                ))}
              </div>
            </div>
            <div>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--muted)', display: 'block', marginBottom: 5 }}>Known Devices</span>
              {(!profile.known_fingerprints || profile.known_fingerprints.length === 0) ? (
                <span style={{ fontSize: 11, color: 'var(--muted)', fontStyle: 'italic' }}>No trusted device fingerprints yet.</span>
              ) : (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {profile.known_fingerprints.map((fp: string) => (
                    <span key={fp} style={{ padding: '2px 7px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 5, fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--signal)' }}>
                      {fp}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 2px' }}>
            <div className="detail-label">Device Timeline</div>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--muted)', fontWeight: 600 }}>Last {events.length} sessions</span>
          </div>

          <div style={{ flex: 1, overflowY: 'auto', border: '1px solid var(--border)', background: 'var(--void)', borderRadius: 10, padding: 10, maxHeight: 350, display: 'flex', flexDirection: 'column', gap: 8 }}>
            {events.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px 0', color: 'var(--muted)', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                <Clock size={20} style={{ animation: 'blink 1.5s ease infinite' }} />
                <span style={{ fontSize: 11, fontWeight: 600 }}>No recent events logged for this entity.</span>
              </div>
            ) : (
              events.map((evt, i) => {
                const matchingAlert = alerts.find(a => a.event.timestamp === evt.timestamp && a.event.resource_accessed === evt.resource_accessed);
                const isAnomaly = matchingAlert && matchingAlert.attack_type !== 'normal';
                return (
                  <div key={i} style={{
                    background: 'var(--surface)',
                    border: '1px solid var(--border)',
                    borderLeft: isAnomaly ? '3px solid var(--threat)' : '3px solid var(--safe)',
                    borderRadius: 10, padding: '10px 12px',
                    boxShadow: 'var(--shadow-soft)',
                    transition: 'box-shadow 0.2s',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 5 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 700, color: 'var(--signal)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>
                        {evt.resource_accessed}
                      </span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--muted)', flexShrink: 0, textAlign: 'right' }}>
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                        {' '}
                        <span style={{ fontSize: 8 }}>{new Date(evt.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' })}</span>
                      </span>
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '2px 8px', fontSize: 10, color: 'var(--muted)', fontWeight: 500 }}>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{evt.source_ip}</span>
                      <span>•</span>
                      <span>{evt.geo_location}</span>
                      <span>•</span>
                      <span>{evt.auth_method}</span>
                      <span>•</span>
                      <span style={{ fontFamily: 'var(--font-mono)' }}>{evt.session_duration}m</span>
                    </div>
                    {isAnomaly && matchingAlert && (
                      <div style={{ marginTop: 8, padding: '6px 10px', background: 'rgba(240, 68, 68, 0.12)', border: '1px solid rgba(240, 68, 68, 0.35)', borderRadius: 7, fontSize: 10, fontWeight: 500, color: 'var(--threat)', display: 'flex', alignItems: 'flex-start', gap: 6 }}>
                        <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 1 }} />
                        <div>
                          <span style={{ fontWeight: 700, textTransform: 'uppercase', fontSize: 9, display: 'block', marginBottom: 2 }}>
                            {matchingAlert.attack_type.replace(/_/g, ' ')} detected
                          </span>
                          {matchingAlert.explanation_summary}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div style={{ borderTop: '1px solid var(--border)', padding: '10px 20px', background: 'var(--void)', display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--muted)' }}>
        <Info size={12} style={{ color: 'var(--drift)', flexShrink: 0 }} />
        Baseline changes are tracked under Concept Drift. Timelines show the last 100 historical records.
      </div>
    </div>
  );
};
