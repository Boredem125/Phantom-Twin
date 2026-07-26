import React, { useState } from 'react';
import type { Alert } from '../types/PhantomTwin';
import { AlertCard } from './AlertCard';
import { FilterBar } from './FilterBar';
import { AlertTriangle, Info } from 'lucide-react';

interface AlertQueueProps {
  alerts: Alert[];
  onSelectEntity: (entityId: string) => void;
  selectedAlert: Alert | null;
  setSelectedAlert: (alert: Alert | null) => void;
}

export const AlertQueue: React.FC<AlertQueueProps> = ({
  alerts,
  onSelectEntity,
  selectedAlert,
  setSelectedAlert
}) => {
  const [searchId, setSearchId] = useState('');
  const [selectedEntityType, setSelectedEntityType] = useState('');
  const [selectedAttackType, setSelectedAttackType] = useState('');
  const [selectedRiskLevel, setSelectedRiskLevel] = useState('');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const handleResetFilters = () => {
    setSearchId('');
    setSelectedEntityType('');
    setSelectedAttackType('');
    setSelectedRiskLevel('');
  };

  const handleToggleExpand = (alertId: string, alert: Alert) => {
    if (expandedAlertId === alertId) {
      setExpandedAlertId(null);
    } else {
      setExpandedAlertId(alertId);
      setSelectedAlert(alert);
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    if (searchId && !alert.entity_id.toLowerCase().includes(searchId.toLowerCase())) return false;
    if (selectedEntityType && alert.entity_type !== selectedEntityType) return false;
    if (selectedAttackType && alert.attack_type !== selectedAttackType) return false;
    if (selectedRiskLevel && alert.risk_level !== selectedRiskLevel) return false;
    return true;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: '100%' }}>
      <FilterBar
        searchId={searchId}
        setSearchId={setSearchId}
        selectedEntityType={selectedEntityType}
        setSelectedEntityType={setSelectedEntityType}
        selectedAttackType={selectedAttackType}
        setSelectedAttackType={setSelectedAttackType}
        selectedRiskLevel={selectedRiskLevel}
        setSelectedRiskLevel={setSelectedRiskLevel}
        onReset={handleResetFilters}
      />

      <div 
        className="queue-scroll"
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: '10px',
          overflowY: 'auto',
          paddingRight: '4px',
          maxHeight: 'calc(100vh - 280px)',
          minHeight: '400px',
        }}
      >
        {filteredAlerts.length === 0 ? (
          <div 
            className="queue-empty"
            style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius-xl)',
              padding: '48px 24px',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '12px',
              flex: 1,
            }}
          >
            <div className="queue-empty-icon">
              <AlertTriangle size={22} />
            </div>
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--signal)', marginBottom: 4 }}>
                {alerts.length === 0 ? 'Waiting for events...' : 'No matching incidents found'}
              </h3>
              <p style={{ fontSize: 11, color: 'var(--muted)', maxWidth: 280 }}>
                {alerts.length === 0
                  ? 'Start the demo replay script to populate the live alert stream.'
                  : 'Try modifying your filter settings or search query.'}
              </p>
            </div>
          </div>
        ) : (
          filteredAlerts.map(alert => (
            <AlertCard
              key={alert.alert_id}
              alert={alert}
              isExpanded={expandedAlertId === alert.alert_id}
              onToggle={() => handleToggleExpand(alert.alert_id, alert)}
              onSelectEntity={onSelectEntity}
              isSelectedForView={selectedAlert?.alert_id === alert.alert_id}
            />
          ))
        )}
      </div>

      <div className="queue-footer">
        <Info size={13} style={{ color: 'var(--drift)', flexShrink: 0 }} />
        <span>Queue updates live via WebSockets. Critical (85+) and High (70–85) alerts spawn live Phantom Twin decoys.</span>
      </div>
    </div>
  );
};
