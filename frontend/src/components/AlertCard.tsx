import React from 'react';
import type { Alert } from '../types/PhantomTwin';
import { ChevronDown, ChevronUp, User, Cpu, Server, MapPin, Eye, Clock, FileText } from 'lucide-react';

interface AlertCardProps {
  alert: Alert;
  isExpanded: boolean;
  onToggle: () => void;
  onSelectEntity: (entityId: string) => void;
  isSelectedForView: boolean;
}

export const AlertCard: React.FC<AlertCardProps> = ({
  alert, isExpanded, onToggle, onSelectEntity, isSelectedForView
}) => {
  const sevClass = alert.risk_level === 'CRITICAL' ? 'sev-critical'
                 : alert.risk_level === 'HIGH'     ? 'sev-high'
                 : alert.risk_level === 'MEDIUM'   ? 'sev-medium'
                 : 'sev-low';

  const badgeSevClass = alert.risk_level === 'CRITICAL' ? 'badge badge-critical'
                      : alert.risk_level === 'HIGH'     ? 'badge badge-high'
                      : alert.risk_level === 'MEDIUM'   ? 'badge badge-medium'
                      : 'badge badge-low';

  const riskScoreClass = alert.risk_score > 80 ? 'risk-score high'
                       : alert.risk_score > 50 ? 'risk-score medium'
                       : 'risk-score low';

  const formattedTime = new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const formattedDate = new Date(alert.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });

  const getEntityIcon = (type: string) => {
    if (type === 'service_account') return <Server size={14} style={{ color: 'var(--muted)' }} />;
    if (type === 'edge_device')     return <Cpu size={14} style={{ color: 'var(--muted)' }} />;
    return <User size={14} style={{ color: 'var(--muted)' }} />;
  };

  const formatFeatureName = (name: string) =>
    name.replace(/_/g, ' ').replace(/\b(fp|ip)\b/g, m => m.toUpperCase())
        .replace(/^\w/, c => c.toUpperCase());

  const leftBorderColor = alert.risk_level === 'CRITICAL' ? 'var(--threat)'
                        : alert.risk_level === 'HIGH'     ? 'var(--warn)'
                        : alert.risk_level === 'MEDIUM'   ? '#F59E0B'
                        : 'var(--muted)';

  return (
    <div 
      className={`alert-card ${sevClass} fade-in${isSelectedForView ? ' selected' : ''}`}
      style={{
        display: 'block',
        flexShrink: 0,
        minHeight: '60px',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-xl)',
        marginBottom: '10px',
        borderLeft: `4px solid ${leftBorderColor}`,
        boxShadow: isSelectedForView ? 'var(--shadow-active)' : 'var(--shadow-soft)',
        overflow: 'hidden',
        transition: 'all 0.2s',
      }}
    >
      {/* Header */}
      <div 
        className="alert-card-header" 
        onClick={onToggle}
        style={{
          padding: '14px 16px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '12px',
          cursor: 'pointer',
        }}
      >
        <div className="alert-tags">
          {/* Severity Badge */}
          <span className={badgeSevClass}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'currentColor', display: 'inline-block' }} />
            {alert.risk_level}
          </span>

          {/* Attack Type */}
          {alert.attack_type !== 'normal' ? (
            <span className="badge badge-attack">
              {alert.attack_type.replace(/_/g, ' ').toUpperCase()}
            </span>
          ) : (
            <span className="badge badge-normal">NOMINAL ACCESS</span>
          )}

          {/* Decoy Badge */}
          {alert.phantom_activated && (
            <span className="badge badge-decoy">
              <Eye size={10} />
              DECOY ACTIVE
            </span>
          )}

          {/* Entity ID */}
          <span className="badge-entity">
            {getEntityIcon(alert.entity_type)}
            {alert.entity_id}
          </span>

          {/* Location */}
          <span className="badge-geo">
            <MapPin size={12} />
            {alert.event.geo_location}
          </span>
        </div>

        {/* Right: timestamp + toggle */}
        <div className="alert-card-right">
          <div className="alert-time">
            <div className="alert-time-value">{formattedTime}</div>
            <div className="alert-time-date">{formattedDate}</div>
          </div>
          <div className="toggle-btn">
            {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </div>
        </div>
      </div>

      {/* Expanded Detail */}
      {isExpanded && (
        <div className="alert-detail">
          {/* Rationale */}
          <div className="detail-card">
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
              <div className="detail-icon">
                <FileText size={15} />
              </div>
              <div>
                <div className="detail-label">Incident Rationale</div>
                <p className="detail-text">{alert.explanation}</p>
              </div>
            </div>
          </div>

          {/* Feature Deviations Table */}
          <div>
            <div className="detail-label" style={{ padding: '0 2px', marginBottom: 8 }}>
              Behavioral Deviations
            </div>
            <table className="feature-table">
              <thead>
                <tr>
                  <th>Behavioral Attribute</th>
                  <th>Expected Baseline</th>
                  <th>Observed Activity</th>
                  <th style={{ textAlign: 'right' }}>Deviation</th>
                  <th style={{ textAlign: 'right' }}>Weight</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(alert.feature_attribution).map(([key, item]) => {
                  const isHighDev = item.score > 0.5;
                  const scoreClass = item.score > 0.8 ? 'dev-score high' : item.score > 0.4 ? 'dev-score medium' : 'dev-score low';
                  return (
                    <tr key={key} className={isHighDev ? 'high-dev' : ''}>
                      <td className="td-name">
                        <span className={`dev-dot ${isHighDev ? 'high' : 'normal'}`} />
                        {formatFeatureName(key)}
                      </td>
                      <td className="td-mono">
                        {Array.isArray(item.baseline) ? `[${item.baseline.length} fingerprints]` : String(item.baseline)}
                      </td>
                      <td className={`td-mono ${isHighDev ? 'high' : ''}`}>
                        {String(item.observed)}
                      </td>
                      <td className="td-right">
                        <span className={scoreClass}>
                          {(item.score * 100).toFixed(0)}%
                        </span>
                      </td>
                      <td className="td-right" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--muted)' }}>
                        {(item.weight * 100).toFixed(0)}%
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Action Row */}
          <div className="action-row">
            <div className="risk-info">
              <span>Overall Risk score:</span>
              <span className={riskScoreClass}>{alert.risk_score}/100</span>
              <span style={{ color: 'var(--border)' }}>|</span>
              <span>Confidence:</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--signal)' }}>
                {(alert.confidence * 100).toFixed(0)}%
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                className="btn-action"
                onClick={(e) => { e.stopPropagation(); onSelectEntity(alert.entity_id); }}
              >
                <Clock size={13} style={{ color: 'var(--muted)' }} />
                View Timeline History
              </button>

              {alert.phantom_activated && (
                <div className="decoy-running">
                  <span className="decoy-dot" />
                  Decoy Running on Endpoint
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
