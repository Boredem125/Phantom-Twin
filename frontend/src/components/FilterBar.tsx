import React from 'react';
import { Search, Filter, X } from 'lucide-react';

interface FilterBarProps {
  searchId: string;
  setSearchId: (v: string) => void;
  selectedEntityType: string;
  setSelectedEntityType: (v: string) => void;
  selectedAttackType: string;
  setSelectedAttackType: (v: string) => void;
  selectedRiskLevel: string;
  setSelectedRiskLevel: (v: string) => void;
  onReset: () => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  searchId, setSearchId,
  selectedEntityType, setSelectedEntityType,
  selectedAttackType, setSelectedAttackType,
  selectedRiskLevel, setSelectedRiskLevel,
  onReset
}) => {
  const hasFilters = searchId || selectedEntityType || selectedAttackType || selectedRiskLevel;

  return (
    <div className="filter-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--muted)', fontSize: 12 }}>
        <Filter size={14} />
        <span style={{ fontWeight: 600 }}>Filter</span>
      </div>

      <div className="filter-search">
        <Search size={13} style={{ color: 'var(--muted)', flexShrink: 0 }} />
        <input
          type="text"
          placeholder="Search entity ID..."
          value={searchId}
          onChange={e => setSearchId(e.target.value)}
        />
      </div>

      <select
        className="filter-select"
        value={selectedEntityType}
        onChange={e => setSelectedEntityType(e.target.value)}
      >
        <option value="">All Entity Types</option>
        <option value="user">User</option>
        <option value="service_account">Service Account</option>
        <option value="edge_device">Edge Device</option>
      </select>

      <select
        className="filter-select"
        value={selectedAttackType}
        onChange={e => setSelectedAttackType(e.target.value)}
      >
        <option value="">All Attack Types</option>
        <option value="brute_force">Brute Force</option>
        <option value="credential_stuffing">Credential Stuffing</option>
        <option value="impossible_travel">Impossible Travel</option>
        <option value="lateral_movement">Lateral Movement</option>
        <option value="low_and_slow">Low & Slow</option>
        <option value="device_spoofing">Device Spoofing</option>
        <option value="normal">Normal</option>
      </select>

      <select
        className="filter-select"
        value={selectedRiskLevel}
        onChange={e => setSelectedRiskLevel(e.target.value)}
      >
        <option value="">All Risk Levels</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>

      {hasFilters && (
        <button className="btn-reset" onClick={onReset}>
          <X size={12} />
          Reset
        </button>
      )}
    </div>
  );
};
