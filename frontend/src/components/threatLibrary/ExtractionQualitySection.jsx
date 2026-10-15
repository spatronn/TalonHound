import React, { useState } from 'react';
import { ToneBadge } from './reportPageParts.jsx';
import { describeExtractionQuality } from './extractionQualityUi.js';

/**
 * Overview "Extraction quality": read-only automatic checks (tl-quality-v1).
 * Signals for review, never confirmed errors; no parser internals.
 */
export default function ExtractionQualitySection({ quality }) {
  const model = describeExtractionQuality(quality);
  const [expanded, setExpanded] = useState(model.attention > 0);

  return (
    <section className="tl-intel tl-quality" data-testid="extraction-quality" aria-labelledby="tl-quality-heading">
      <h2 className="tl-heading" id="tl-quality-heading">Extraction quality</h2>
      <div className="tl-quality__summary">
        <ToneBadge tone={model.tone}>{model.statusLabel}</ToneBadge>
        <span className="tl-quality__headline" data-testid="extraction-quality-headline">{model.headline}</span>
        {model.items.length ? (
          <button
            type="button"
            className="tl-ghost-btn tl-quality__toggle"
            aria-expanded={expanded}
            aria-controls="tl-quality-list"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? 'Hide details' : 'Show details'}
          </button>
        ) : null}
      </div>
      {model.assessed && model.items.length ? (
        <p className="tl-quality__disclaimer">{model.disclaimer}</p>
      ) : null}
      {expanded && model.items.length ? (
        <ul className="tl-quality__list" id="tl-quality-list" data-testid="extraction-quality-list">
          {model.items.map((item) => (
            <li key={item.key} className={`tl-quality__item tl-quality__item--${item.severity}`} data-code={item.code}>
              <div className="tl-quality__item-head">
                <ToneBadge tone={item.tone}>{item.severityLabel}</ToneBadge>
                <strong className="tl-quality__title">{item.title}</strong>
              </div>
              <p className="tl-quality__why">{item.why}</p>
              {item.context ? <p className="tl-quality__context">{item.context}</p> : null}
              {item.values.length ? (
                <ul className="tl-quality__values" aria-label="Affected values">
                  {item.values.map((v) => (
                    <li key={`${v.type}:${v.value}`}>
                      <span className="tl-quality__type">{v.typeLabel}</span>
                      <code className="tl-quality__value">{v.value}</code>
                    </li>
                  ))}
                  {item.moreValues ? <li className="tl-quality__more">+{item.moreValues} more</li> : null}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
