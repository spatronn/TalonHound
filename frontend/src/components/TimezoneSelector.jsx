import React, { useEffect, useMemo, useState } from 'react';
import {
  fetchSupportedTimezones,
  filterTimezones,
  ensureTimezoneInOptions
} from '../lib/timezones.js';

const defaultStyles = {
  label: {
    display: 'block',
    fontSize: 13,
    color: '#cbd5e1',
    marginBottom: 6,
    fontWeight: 600
  },
  input: {
    width: '100%',
    boxSizing: 'border-box',
    marginBottom: 14,
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#0b1220',
    color: '#e2e8f0'
  },
  select: {
    width: '100%',
    boxSizing: 'border-box',
    marginBottom: 16,
    padding: '10px 12px',
    borderRadius: 8,
    border: '1px solid #334155',
    background: '#0b1220',
    color: '#e2e8f0'
  },
  error: {
    color: '#fca5a5',
    marginBottom: 12,
    fontSize: 13
  },
  muted: {
    color: '#94a3b8',
    marginBottom: 12,
    fontSize: 13
  }
};

/**
 * Searchable IANA timezone selector backed by GET /api/system/timezones.
 */
export default function TimezoneSelector({
  value,
  onChange,
  disabled = false,
  id = 'timezone-select',
  filterId = 'timezone-filter',
  placeholder = 'Select a timezone…',
  filterPlaceholder = 'e.g. London, Istanbul, New_York, Pacific/',
  filterLabel = 'Search IANA timezones',
  selectLabel = 'System Timezone',
  showFilter = true,
  styles = defaultStyles,
  selectStyle,
  inputStyle,
  labelStyle
}) {
  const [zones, setZones] = useState([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError('');
      try {
        const list = await fetchSupportedTimezones();
        if (!cancelled) setZones(list);
      } catch (err) {
        if (!cancelled) {
          setError(err?.response?.data?.message || err.message || 'Failed to load timezone list');
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const optionZones = useMemo(
    () => ensureTimezoneInOptions(zones, value),
    [zones, value]
  );

  const filteredZones = useMemo(
    () => filterTimezones(optionZones, filter),
    [optionZones, filter]
  );

  const mergedLabelStyle = { ...defaultStyles.label, ...labelStyle };
  const mergedInputStyle = { ...defaultStyles.input, ...inputStyle };
  const mergedSelectStyle = { ...defaultStyles.select, ...selectStyle, ...styles.select };

  return (
    <>
      {showFilter ? (
        <>
          <label style={mergedLabelStyle} htmlFor={filterId}>{filterLabel}</label>
          <input
            id={filterId}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder={filterPlaceholder}
            style={mergedInputStyle}
            disabled={disabled || loading || Boolean(error)}
          />
        </>
      ) : null}

      <label style={mergedLabelStyle} htmlFor={id}>{selectLabel}</label>
      {loading ? (
        <div style={styles.muted || defaultStyles.muted}>Loading timezones…</div>
      ) : null}
      {error ? (
        <div style={styles.error || defaultStyles.error} role="alert">{error}</div>
      ) : null}
      <select
        id={id}
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        style={mergedSelectStyle}
        disabled={disabled || loading || Boolean(error)}
      >
        <option value="">{placeholder}</option>
        {filteredZones.map((z) => (
          <option key={z} value={z}>{z}</option>
        ))}
      </select>
    </>
  );
}
