export const IOC_SOURCE_TIMESTAMP_PRESENTATION = Object.freeze({
  first: Object.freeze({
    label: 'First seen in source',
    tooltip: 'The time TalonHound first observed this IOC in this source.'
  }),
  last: Object.freeze({
    label: 'Last confirmed in source',
    tooltip: 'The latest time TalonHound confirmed that this IOC was still present in the source. This does not mean the IOC changed or was re-imported.'
  })
});
