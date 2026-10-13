import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api.js';
import ImportIntelligenceModal from './ImportIntelligenceModal.jsx';
import {
  REPORT_LIST_IMPORTED_OPTIONS,
  REPORT_LIST_PAGE_SIZE,
  REPORT_LIST_PAGE_SIZE_OPTIONS,
  REPORT_LIST_SEARCH_DEBOUNCE_MS,
  REPORT_LIST_SEARCH_MAX_LENGTH,
  REPORT_LIST_SOURCE_OPTIONS,
  REPORT_LIST_STATUS_TABS,
  REPORT_LIST_TLP_OPTIONS,
  buildReportListPageItems,
  buildReportListUrlSearchParams,
  cycleReportListSort,
  describeReportListEmptyState,
  describeReportListPagination,
  describeReportListSortMenu,
  formatReportListShowingLabel,
  hasActiveReportListFilters,
  normalizeReportListSearch,
  parseReportListSortMenuValue,
  parseReportListUrlState,
  reportListAriaSort,
  reportListSortMarker
} from './reportList.js';
import { createReportListLoader } from './reportListLoader.js';
import {
  describeReportImported,
  describeReportIntelligence,
  describeReportListStatus,
  describeReportSource,
  splitReportListTags
} from './reportListRow.js';
import { ListIcons, sourceTypeIcon } from './reportListIcons.jsx';
import { formatPublicationDate, publicationDateTitle } from './publicationDate.js';
import { isElevatedTlp, tlpColors, tlpDisplay } from './tlp.jsx';
import { ui } from './styles.js';
import './reportList.css';

const REPORT_PATH = '/threat-intelligence/threat-library';
const COLUMN_COUNT = 7;

function SortButton({ label, column, sort, order, onCycle }) {
  const active = sort === column;
  const marker = reportListSortMarker(sort, order, column);
  return (
    <button
      type="button"
      className={`tl-lib-th-btn${active ? ' is-active' : ''}`}
      onClick={() => onCycle(column)}
      aria-label={
        active
          ? `${label}, sorted ${order === 'desc' ? 'descending' : 'ascending'}. Activate to cycle sort.`
          : `Sort by ${label}`
      }
    >
      {label}
      {marker ? <span aria-hidden="true">{marker}</span> : null}
    </button>
  );
}

function SortableTh({ label, column, sort, order, onCycle }) {
  return (
    <th scope="col" aria-sort={reportListAriaSort(sort, order, column)}>
      <SortButton label={label} column={column} sort={sort} order={order} onCycle={onCycle} />
    </th>
  );
}

/** Intelligence = Entities / Indicators / Matched, each still sortable on its own. */
const INTEL_COLUMNS = [
  { column: 'entities', label: 'Entities' },
  { column: 'indicators', label: 'Indicators' },
  { column: 'matched', label: 'Matched' }
];

function IntelligenceTh({ sort, order, onCycle }) {
  const active = INTEL_COLUMNS.find((c) => c.column === sort);
  return (
    <th scope="col" aria-sort={active ? reportListAriaSort(sort, order, active.column) : 'none'}>
      <span className="tl-lib-sr-only">Intelligence: </span>
      <div className="tl-lib-intel-head">
        {INTEL_COLUMNS.map((c) => (
          <SortButton key={c.column} label={c.label} column={c.column} sort={sort} order={order} onCycle={onCycle} />
        ))}
      </div>
    </th>
  );
}

function FilterSelect({ id, label, value, options, onChange, className = '' }) {
  return (
    <label htmlFor={id} className={`tl-lib-filter${value ? ' is-active' : ''}${className ? ` ${className}` : ''}`}>
      <span className="tl-lib-filter__caption" id={`${id}-label`}>{label}</span>
      <select
        id={id}
        className="tl-lib-filter__select"
        aria-labelledby={`${id}-label`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      >
        {options.map((o) => (
          <option key={o.value || 'all'} value={o.value}>{o.label}</option>
        ))}
      </select>
    </label>
  );
}

/**
 * Same colours and text as TlpBadge; the label may break after "+" so
 * TLP:AMBER+STRICT wraps inside a narrow column instead of being clipped.
 */
function ListTlpBadge({ tlp, display }) {
  const { border, bg, color } = tlpColors(tlp);
  const [head, ...rest] = tlpDisplay(tlp, display).split('+');
  return (
    <span className="tl-lib-tlp-badge" style={{ borderColor: border, background: bg, color }}>
      {head}
      {rest.map((part, i) => <React.Fragment key={i}>+<wbr />{part}</React.Fragment>)}
    </span>
  );
}

function ReportRow({ row, onOpen }) {
  const source = describeReportSource(row);
  const status = describeReportListStatus(row);
  const tags = splitReportListTags(row.tags);
  const imported = describeReportImported(row);
  const title = row.title || 'Untitled report';
  return (
    <tr className="tl-lib-row" onClick={(e) => onOpen(e, row)}>
      <td>
        <div className="tl-lib-report">
          <span className="tl-lib-report__icon" title={source.typeLabel}>{sourceTypeIcon(source.type)}</span>
          <div className="tl-lib-report__body">
            <Link to={`${REPORT_PATH}/${row.id}`} className="tl-lib-report__title" title={title}>{title}</Link>
            {tags.visible.length ? (
              <ul className="tl-lib-tags" aria-label="Report tags">
                {tags.visible.map((t, i) => (
                  <li key={t.id} className="tl-lib-tag" data-tag-index={i} title={t.name}>{t.name}</li>
                ))}
                {/* One "+N" per visible-chip count; CSS shows the one matching the cell width. */}
                {tags.overflow.map((o) => (
                  <li key={o.shown} className="tl-lib-tag tl-lib-tag--more" data-tags-shown={o.shown} title={o.title}>
                    +{o.count}
                    <span className="tl-lib-sr-only"> more: {o.title}</span>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        </div>
      </td>
      <td>
        <div className="tl-lib-source">
          <span className="tl-lib-source__label" title={source.title}>{source.label}</span>
          {source.href ? (
            <a
              href={source.href}
              target="_blank"
              rel="noopener noreferrer"
              className="tl-lib-source__link"
              title={`Open source in a new tab: ${source.href}`}
              aria-label={`Open source ${source.label} in a new tab`}
            >
              {ListIcons.external}
            </a>
          ) : null}
        </div>
        <div className="tl-lib-source__type">{source.typeLabel}</div>
      </td>
      <td>
        <ListTlpBadge tlp={row.tlp} display={row.tlp_display} />
        {isElevatedTlp(row.tlp) ? (
          <div className="tl-lib-tlp-note" title="Elevated TLP — handle carefully">Handle carefully</div>
        ) : null}
      </td>
      <td>
        <div className="tl-lib-intel">
          {describeReportIntelligence(row).map((m) => (
            <div key={m.key} className={`tl-lib-metric${m.muted ? ' is-muted' : ''}`} title={m.title}>
              <span className="tl-lib-metric__value">{m.value}</span>
              <span className="tl-lib-metric__label">{m.label}</span>
            </div>
          ))}
        </div>
      </td>
      <td>
        <span className={`tl-lib-status-pill tl-lib-tone--${status.tone}`}>
          <span className="tl-lib-status-pill__dot" aria-hidden="true" />
          <span className="tl-lib-status-pill__text">{status.label}</span>
        </span>
      </td>
      <td className="tl-lib-date" title={publicationDateTitle(row) || undefined}>
        {formatPublicationDate(row) || '—'}
      </td>
      <td className="tl-lib-date" title={imported?.title}>
        {imported ? (
          <>
            <div>{imported.date}</div>
            <div className="tl-lib-muted">{imported.time}</div>
          </>
        ) : '—'}
      </td>
    </tr>
  );
}

export default function ThreatLibraryPage({ AppShell, useSession }) {
  const { isAdmin, canWrite } = useSession();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  // The URL is the single source of truth for the debounced search term, the
  // page, the rows per page, the optional explicit sort and the filters
  // (?search=&status=&tlp=&source=&imported=&page=&limit=&sort=&order=), so
  // reload, Back/Forward and shared links all land on the same list state and
  // nothing can fight the router.
  const { search, page, pageSize, sort, order, status, tlp, source, imported } = useMemo(
    () => parseReportListUrlState(searchParams),
    [searchParams]
  );
  const filters = useMemo(() => ({ status, tlp, source, imported }), [status, tlp, source, imported]);
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  // Status-tab counts from the API (whole filtered set); null = not reported.
  const [phaseCounts, setPhaseCounts] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [importOpen, setImportOpen] = useState(false);
  // searchInput follows every keystroke; the URL `search` is its debounced,
  // trimmed form (same split as the threat-actor list).
  const [searchInput, setSearchInput] = useState(search);
  // Overlapping list requests (search, filters, page, Refresh) go through one
  // loader: only the most recently issued response may land, and an
  // out-of-range page is clamped to the last valid one instead of stranding the user.
  const loaderRef = useRef(null);
  if (!loaderRef.current) {
    loaderRef.current = createReportListLoader({
      pageSize: REPORT_LIST_PAGE_SIZE,
      fetchPage: async (params, signal) => (await api.get('/threat-library/reports', { params, signal })).data
    });
  }

  // react-router recreates searchParams AND setSearchParams on every URL change;
  // read both through a ref so setListUrl (and therefore load) keeps one identity
  // and a URL rewrite never re-issues the list request by itself.
  const routerRef = useRef({ searchParams, setSearchParams });
  routerRef.current = { searchParams, setSearchParams };
  const setListUrl = useCallback((next) => {
    const params = buildReportListUrlSearchParams(next);
    const router = routerRef.current;
    if (params.toString() !== router.searchParams.toString()) router.setSearchParams(params, { replace: true });
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    const result = await loaderRef.current.load({ search, page, pageSize, sort, order, ...filters });
    if (result.kind === 'stale') return;
    if (result.kind === 'clamped') {
      // Result set shrank below this page (search / filter narrowed, rows
      // deleted): keep the loading state and reload the last valid page.
      setTotal(result.total);
      setPhaseCounts(result.phaseCounts);
      setListUrl({ search, page: result.page, pageSize, sort, order, ...filters });
      return;
    }
    if (result.kind === 'error') {
      setError(result.message);
      setItems([]);
      setTotal(0);
      setPhaseCounts(null);
    } else {
      setItems(result.items);
      setTotal(result.total);
      setPhaseCounts(result.phaseCounts);
    }
    setLoading(false);
  }, [search, page, pageSize, sort, order, filters, setListUrl]);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  useEffect(() => () => loaderRef.current?.abort(), []);

  // Debounced term -> URL. A new term (or clearing it) always starts from page 1
  // and keeps the active filters and sort.
  useEffect(() => {
    const t = setTimeout(() => {
      const next = normalizeReportListSearch(searchInput);
      if (next !== search) setListUrl({ search: next, page: 1, pageSize, sort, order, ...filters });
    }, REPORT_LIST_SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [searchInput, search, pageSize, sort, order, filters, setListUrl]);

  // URL term changed underneath the field (Back/Forward, shared link): reflect it,
  // but leave the raw input alone while it already normalises to the same term.
  useEffect(() => {
    setSearchInput((prev) => (normalizeReportListSearch(prev) === search ? prev : search));
  }, [search]);

  // Canonicalise a hand-typed URL (page=1, padded search, junk page / limit /
  // filter values) once; the serialised form of the parsed state is a fixed
  // point, so this cannot loop.
  useEffect(() => {
    setListUrl({ search, page, pageSize, sort, order, ...filters });
  }, [search, page, pageSize, sort, order, filters, setListUrl]);

  const goToPage = (next) => setListUrl({ search, page: next, pageSize, sort, order, ...filters });
  // A new page size restarts at page 1 so the first visible row is never skipped.
  const changePageSize = (next) => setListUrl({ search, page: 1, pageSize: next, sort, order, ...filters });
  const cycleSort = (column) => {
    const next = cycleReportListSort(sort, order, column);
    setListUrl({ search, page: 1, pageSize, sort: next.sort, order: next.order, ...filters });
  };
  // The sort menu writes the same ?sort=&order= state the headers cycle.
  const chooseSort = (value) => {
    const next = parseReportListSortMenuValue(value);
    setListUrl({ search, page: 1, pageSize, sort: next.sort, order: next.order, ...filters });
  };
  // Any filter change (toolbar or status tab) restarts at page 1.
  const changeFilter = (key, value) => setListUrl({ search, page: 1, pageSize, sort, order, ...filters, [key]: value });
  // Clear search + filters; rows per page and sort are view preferences and stay.
  const clearFilters = () => {
    setSearchInput('');
    setListUrl({ search: '', page: 1, pageSize, sort, order });
  };

  const filtered = Object.values(filters).some(Boolean);
  const narrowing = hasActiveReportListFilters({ search, ...filters }) || normalizeReportListSearch(searchInput) !== '';
  const pagination = describeReportListPagination({ page, total, pageSize });
  const pageItems = buildReportListPageItems(pagination.page, pagination.totalPages);
  const sortMenu = describeReportListSortMenu(sort, order);
  // Rows already on screen stay visible (dimmed) while the next request runs,
  // so filtering / paging never flashes an empty table.
  const showRows = items.length > 0;
  const emptyState = describeReportListEmptyState({
    loading: loading && !showRows,
    itemCount: items.length,
    total,
    search,
    canWrite,
    error,
    filters
  });

  function openReport(e, row) {
    // Links / buttons inside the row handle themselves (incl. Ctrl/Cmd-click
    // on the title); a text selection drag is not a click.
    if (e.target instanceof Element && e.target.closest('a, button, input, select, label')) return;
    if (typeof window !== 'undefined' && String(window.getSelection?.() || '').length > 0) return;
    navigate(`${REPORT_PATH}/${row.id}`);
  }

  function onImported(report) {
    if (report?.id) {
      navigate(`${REPORT_PATH}/${report.id}`);
      return;
    }
    load().catch(() => {});
  }

  return (
    <AppShell>
      <section style={ui.section} className="tl-lib">
        <div className="tl-lib-header">
          <div className="tl-lib-header__title">
            <h1 style={ui.pageTitle}>Threat Library</h1>
            <p className="tl-lib-header__subtitle">
              Import vendor reports and intelligence bundles, review extracted indicators, and promote matched IOCs.
            </p>
          </div>
          <div className="tl-lib-header__actions">
            {isAdmin ? (
              <Link to={`${REPORT_PATH}/ai-settings`} style={ui.btn} className="tl-lib-header__link">
                {ListIcons.settings}
                AI Settings
              </Link>
            ) : null}
            <button type="button" style={ui.btn} onClick={() => load().catch(() => {})}>
              {ListIcons.refresh}
              Refresh
            </button>
            {canWrite ? (
              <button type="button" style={ui.btnPrimary} onClick={() => setImportOpen(true)}>
                {ListIcons.upload}
                Import Intelligence
              </button>
            ) : null}
          </div>
        </div>

        <div className="tl-lib-toolbar" role="search" aria-label="Search and filter reports">
          <div className="tl-lib-search">
            <label htmlFor="tl-report-search" className="tl-lib-sr-only">Search reports</label>
            <span className="tl-lib-search__icon">{ListIcons.search}</span>
            <input
              id="tl-report-search"
              type="search"
              className="tl-lib-search__input"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Escape') setSearchInput(''); }}
              placeholder="Search reports, titles, sources, tags..."
              maxLength={REPORT_LIST_SEARCH_MAX_LENGTH}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
          <FilterSelect id="tl-filter-tlp" label="TLP" value={tlp} options={REPORT_LIST_TLP_OPTIONS} onChange={(v) => changeFilter('tlp', v)} />
          <FilterSelect id="tl-filter-source" label="Source" value={source} options={REPORT_LIST_SOURCE_OPTIONS} onChange={(v) => changeFilter('source', v)} />
          <FilterSelect id="tl-filter-imported" label="Imported" value={imported} options={REPORT_LIST_IMPORTED_OPTIONS} onChange={(v) => changeFilter('imported', v)} />
          <FilterSelect
            id="tl-report-sort"
            label="Sort"
            value={sortMenu.value}
            options={sortMenu.options}
            onChange={chooseSort}
            className="tl-lib-filter--sort"
          />
        </div>

        <div className="tl-lib-statusbar">
          <div className="tl-lib-status-tabs" role="group" aria-label="Filter by status">
            {REPORT_LIST_STATUS_TABS.map((tab) => {
              const count = phaseCounts ? phaseCounts[tab.countKey] : null;
              return (
                <button
                  key={tab.countKey}
                  type="button"
                  className={`tl-lib-status-tab tl-lib-tone--${tab.tone}`}
                  aria-pressed={status === tab.value}
                  aria-label={count != null ? `${tab.label}, ${count.toLocaleString('en-US')} reports` : tab.label}
                  title={tab.title}
                  onClick={() => changeFilter('status', tab.value)}
                >
                  <span className="tl-lib-status-tab__dot" aria-hidden="true" />
                  {tab.label}
                  {count != null ? (
                    <span className="tl-lib-status-tab__count" aria-hidden="true">{count.toLocaleString('en-US')}</span>
                  ) : null}
                </button>
              );
            })}
          </div>
          {narrowing ? (
            <button type="button" className="tl-lib-clear" onClick={clearFilters}>Clear filters</button>
          ) : null}
        </div>

        <div className={`tl-lib-table-wrap${loading && showRows ? ' is-updating' : ''}`} aria-busy={loading}>
          <table className="tl-lib-table">
            <colgroup>
              <col className="tl-lib-col--report" />
              <col className="tl-lib-col--source" />
              <col className="tl-lib-col--tlp" />
              <col className="tl-lib-col--intel" />
              <col className="tl-lib-col--status" />
              <col className="tl-lib-col--published" />
              <col className="tl-lib-col--imported" />
            </colgroup>
            <thead>
              <tr>
                <SortableTh label="Report" column="report" sort={sort} order={order} onCycle={cycleSort} />
                <SortableTh label="Source" column="source" sort={sort} order={order} onCycle={cycleSort} />
                <SortableTh label="TLP" column="tlp" sort={sort} order={order} onCycle={cycleSort} />
                <IntelligenceTh sort={sort} order={order} onCycle={cycleSort} />
                <SortableTh label="Status" column="status" sort={sort} order={order} onCycle={cycleSort} />
                <SortableTh label="Published" column="published" sort={sort} order={order} onCycle={cycleSort} />
                <SortableTh label="Imported" column="imported" sort={sort} order={order} onCycle={cycleSort} />
              </tr>
            </thead>
            <tbody>
              {emptyState.kind === 'loading' ? (
                <tr>
                  <td colSpan={COLUMN_COUNT} className="tl-lib-placeholder" data-testid="report-list-loading">
                    <span className="tl-lib-spinner" aria-hidden="true" />
                    Loading reports…
                  </td>
                </tr>
              ) : emptyState.kind !== 'none' ? (
                <tr>
                  <td
                    colSpan={COLUMN_COUNT}
                    className={`tl-lib-placeholder tl-lib-placeholder--${emptyState.kind}`}
                    data-testid={`report-list-${emptyState.kind}`}
                    role={emptyState.kind === 'error' ? 'alert' : undefined}
                  >
                    <div className="tl-lib-placeholder__title">{emptyState.message}</div>
                    {emptyState.kind === 'error' ? <div className="tl-lib-placeholder__hint">{error}</div> : null}
                    {emptyState.hint ? <div className="tl-lib-placeholder__hint">{emptyState.hint}</div> : null}
                    {emptyState.kind === 'no_match' ? (
                      <div className="tl-lib-placeholder__actions">
                        <button type="button" onClick={clearFilters}>Clear filters</button>
                      </div>
                    ) : null}
                    {emptyState.kind === 'error' ? (
                      <div className="tl-lib-placeholder__actions">
                        <button type="button" onClick={() => load().catch(() => {})}>Try again</button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ) : items.map((row) => (
                <ReportRow key={row.id} row={row} onOpen={openReport} />
              ))}
            </tbody>
          </table>
        </div>

        {total > 0 ? (
          <div className="tl-lib-footer">
            <div aria-live="polite">
              {formatReportListShowingLabel({ from: pagination.from, to: pagination.to, total, search, filtered })}
              {loading ? ' · Updating…' : ''}
            </div>
            <div className="tl-lib-footer__pager">
              <label htmlFor="tl-report-page-size" className="tl-lib-footer__size">
                Rows per page
                <select
                  id="tl-report-page-size"
                  value={pageSize}
                  onChange={(e) => changePageSize(Number(e.target.value))}
                >
                  {REPORT_LIST_PAGE_SIZE_OPTIONS.map((n) => (
                    <option key={n} value={n}>{n}</option>
                  ))}
                </select>
              </label>
              <nav className="tl-lib-pager" aria-label="Report list pages">
                <span className="tl-lib-sr-only">{pagination.pageLabel}</span>
                <button
                  type="button"
                  className="tl-lib-pager__btn"
                  aria-label="Previous page"
                  disabled={!pagination.hasPrevious || loading}
                  onClick={() => goToPage(Math.max(1, page - 1))}
                >
                  {ListIcons.chevronLeft}
                </button>
                {pageItems.map((item) => (typeof item === 'number' ? (
                  <button
                    key={item}
                    type="button"
                    className="tl-lib-pager__btn"
                    aria-label={`Page ${item}`}
                    aria-current={item === pagination.page ? 'page' : undefined}
                    disabled={loading && item !== pagination.page}
                    onClick={() => { if (item !== pagination.page) goToPage(item); }}
                  >
                    {item}
                  </button>
                ) : (
                  <span key={item} className="tl-lib-pager__gap" aria-hidden="true">…</span>
                )))}
                <button
                  type="button"
                  className="tl-lib-pager__btn"
                  aria-label="Next page"
                  disabled={!pagination.hasNext || loading}
                  onClick={() => goToPage(page + 1)}
                >
                  {ListIcons.chevronRight}
                </button>
              </nav>
            </div>
          </div>
        ) : null}
      </section>

      <ImportIntelligenceModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={onImported}
        onOpenReport={(reportId) => navigate(`/threat-intelligence/threat-library/${reportId}`)}
      />
    </AppShell>
  );
}
