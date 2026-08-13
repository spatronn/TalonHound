/**
 * Canonical OpenAPI 3.1 document for the programmatic TalonHound API.
 * Served at /api/openapi.json — treat this module as the contract source of truth.
 */

import { API_SCOPE, ACCESS_PROFILE } from '../lib/apiKeyProfiles.js';

export function buildOpenApiDocument({ serverUrl = '/' } = {}) {
  return {
    openapi: '3.1.0',
    info: {
      title: 'TalonHound API',
      version: '1.0.0',
      description: [
        'Programmatic access to TalonHound.',
        '',
        '## Authentication',
        'Management endpoints under `/api/v1` require:',
        '',
        '```',
        'Authorization: Bearer <API_KEY>',
        '```',
        '',
        'Query-string API keys are **not** accepted on `/api/v1`.',
        '',
        'Published Feed pull remains available for backward compatibility:',
        '',
        '```',
        'GET /api/published-feeds/{slug}?api_key=<API_KEY>',
        '```',
        '',
        '## Access profiles & scopes',
        '',
        `| Profile | Scopes |`,
        `| --- | --- |`,
        `| Published Feed (\`${ACCESS_PROFILE.PUBLISHED_FEED}\`) | \`${API_SCOPE.PUBLISHED_FEEDS_READ}\` |`,
        `| IOC Management (\`${ACCESS_PROFILE.IOC_MANAGEMENT}\`) | \`${API_SCOPE.IOC_CREATE}\`, \`${API_SCOPE.IOC_UPDATE}\` |`,
        '',
        'Authorization is scope-based. Profiles are fixed presets — there is no custom scope selector.'
      ].join('\n')
    },
    servers: [{ url: serverUrl }],
    tags: [
      { name: 'IOCs', description: 'Create and update indicators of compromise' },
      { name: 'Published Feeds', description: 'Read-only published feed pull (compatibility)' }
    ],
    components: {
      securitySchemes: {
        ApiKeyBearer: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'API Key',
          description: 'TalonHound API key (th_pf_… or th_ioc_…)'
        }
      },
      schemas: {
        ApiError: {
          type: 'object',
          required: ['error'],
          properties: {
            error: {
              type: 'object',
              required: ['code', 'message', 'request_id'],
              properties: {
                code: {
                  type: 'string',
                  enum: [
                    'VALIDATION_ERROR',
                    'INVALID_IOC_TYPE',
                    'INVALID_IOC_VALUE',
                    'IOC_NOT_FOUND',
                    'INVALID_API_KEY',
                    'API_KEY_DISABLED',
                    'INSUFFICIENT_SCOPE',
                    'RATE_LIMIT_EXCEEDED',
                    'INTERNAL_ERROR'
                  ]
                },
                message: { type: 'string' },
                request_id: { type: 'string' },
                details: {}
              }
            }
          }
        },
        IocCreateRequest: {
          type: 'object',
          required: ['type', 'value'],
          properties: {
            type: { type: 'string', enum: ['ip', 'domain', 'url', 'hash'] },
            value: { type: 'string', description: 'IOC observable value' },
            confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
            classifications: {
              type: 'array',
              items: { type: 'string' },
              description: 'Threat classification slugs (must exist and be active)'
            },
            tags: {
              type: 'array',
              items: { type: 'string' },
              description: 'Existing tag names (resolve-only; unknown names rejected)'
            },
            note: { type: 'string', nullable: true }
          },
          additionalProperties: false
        },
        IocUpdateRequest: {
          type: 'object',
          description: 'Mutable metadata only. type and value are immutable.',
          properties: {
            confidence: { type: 'string', enum: ['low', 'medium', 'high'] },
            classifications: { type: 'array', items: { type: 'string' } },
            tags: { type: 'array', items: { type: 'string' } },
            note: { type: 'string', nullable: true }
          },
          additionalProperties: false
        },
        IocResponse: {
          type: 'object',
          properties: {
            id: { type: 'integer' },
            public_id: { type: 'string', nullable: true },
            type: { type: 'string' },
            value: { type: 'string' },
            confidence: { type: 'string', nullable: true },
            classifications: { type: 'array', items: { type: 'string' } },
            tags: { type: 'array', items: { type: 'string' } },
            note: { type: 'string', nullable: true },
            status: { type: 'string', nullable: true },
            created_at: { type: 'string', format: 'date-time', nullable: true },
            created: { type: 'boolean', description: 'Present on create responses' },
            existing: { type: 'boolean', description: 'true when an existing IOC was returned' }
          }
        }
      }
    },
    paths: {
      '/api/v1/iocs': {
        post: {
          tags: ['IOCs'],
          summary: 'Create IOC',
          description: [
            `Requires scope \`${API_SCOPE.IOC_CREATE}\`.`,
            'Uses the shared TalonHound IOC create service (normalization, validation, dedup, audit).',
            'Source/provenance cannot be spoofed; IOCs are attributed to the system API source and the calling API key.',
            'Submitting a normalized type+value that already exists returns HTTP 200 with `created: false`.'
          ].join('\n\n'),
          security: [{ ApiKeyBearer: [] }],
          'x-required-scopes': [API_SCOPE.IOC_CREATE],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/IocCreateRequest' },
                examples: {
                  domain: {
                    value: {
                      type: 'domain',
                      value: 'malicious-example.com',
                      confidence: 'high',
                      classifications: ['malware_download'],
                      tags: ['external-automation'],
                      note: 'Added by external detection system'
                    }
                  }
                }
              }
            }
          },
          responses: {
            '201': {
              description: 'IOC created',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/IocResponse' },
                  examples: {
                    created: {
                      value: {
                        id: 42,
                        type: 'domain',
                        value: 'malicious-example.com',
                        created: true
                      }
                    }
                  }
                }
              }
            },
            '200': {
              description: 'Existing IOC (duplicate of normalized type+value)',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/IocResponse' },
                  examples: {
                    existing: {
                      value: {
                        id: 42,
                        type: 'domain',
                        value: 'malicious-example.com',
                        created: false,
                        existing: true
                      }
                    }
                  }
                }
              }
            },
            '400': { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '401': { description: 'Invalid or missing API key', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '403': { description: 'Disabled key or insufficient scope', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '500': { description: 'Internal error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } }
          }
        }
      },
      '/api/v1/iocs/{id}': {
        patch: {
          tags: ['IOCs'],
          summary: 'Update IOC metadata',
          description: [
            `Requires scope \`${API_SCOPE.IOC_UPDATE}\`.`,
            '**Immutable:** `type` and `value`. Including either field yields a validation error.',
            'Mutable fields: `confidence`, `classifications`, `tags`, `note`.'
          ].join('\n\n'),
          security: [{ ApiKeyBearer: [] }],
          'x-required-scopes': [API_SCOPE.IOC_UPDATE],
          parameters: [
            {
              name: 'id',
              in: 'path',
              required: true,
              schema: { type: 'integer' }
            }
          ],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/IocUpdateRequest' },
                examples: {
                  noteAndConfidence: {
                    value: {
                      confidence: 'high',
                      note: 'Confirmed by automation'
                    }
                  }
                }
              }
            }
          },
          responses: {
            '200': {
              description: 'Updated',
              content: {
                'application/json': {
                  schema: { $ref: '#/components/schemas/IocResponse' }
                }
              }
            },
            '400': { description: 'Validation error (including immutable field attempts)', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '401': { description: 'Invalid or missing API key', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '403': { description: 'Disabled key or insufficient scope', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '404': { description: 'IOC not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } },
            '500': { description: 'Internal error', content: { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } } }
          }
        }
      },
      '/api/published-feeds/{slug}': {
        get: {
          tags: ['Published Feeds'],
          summary: 'Pull a published feed (compatibility)',
          description: [
            `Requires a Published Feed API key (\`${API_SCOPE.PUBLISHED_FEEDS_READ}\`).`,
            'Authenticate with the `api_key` query parameter (Bearer is not used for this legacy pull path).',
            'A feed may enable TXT, JSON, and/or STIX 2.1 (`formats` is a non-empty subset of `txt`, `json`, `stix`):',
            '- Omit `format` → serve **TXT** when enabled; otherwise the sole enabled format.',
            '- `?format=txt`, `?format=json`, or `?format=stix` selects an enabled format; a disabled format returns **404**.',
            '- Legacy token paths: `/public/feeds/{token}/feed.txt` and `/feed.json`.',
            '- **TXT** returns `text/plain` — one IOC value per line.',
            '- **JSON** returns `application/json` — a `schema_version` "1.0" envelope with a `feed` block '
              + '(name, generated_at, item_count) and an `items` array. Each item carries `type`, `value`, and '
              + '`timestamps`, plus optional `sources`, `classification`, and `enrichment` sections depending on '
              + 'the feed\'s include options. Example:',
            '```json\n{\n  "schema_version": "1.0",\n  "feed": { "name": "Malicious Domains", "generated_at": "2026-08-09T12:30:00Z", "item_count": 1 },\n  "items": [\n    {\n      "type": "domain",\n      "value": "evil-example.com",\n      "timestamps": { "imported_at": "2026-08-07T09:15:22Z", "first_seen_in_source": "2026-08-05T14:22:10Z", "last_confirmed_in_source": "2026-08-09T08:42:31Z" },\n      "sources": [ { "feed_key": "threatfox", "feed_name": "ThreatFox", "first_seen_in_source": "2026-08-05T14:22:10Z", "last_confirmed_in_source": "2026-08-09T08:42:31Z" } ],\n      "classification": { "category": "malware", "confidence": 85, "tags": ["c2", "malware"] },\n      "enrichment": { "virustotal": { "malicious": 12, "suspicious": 3, "harmless": 48, "last_analysis_at": "2026-08-08T17:20:10Z" } }\n    }\n  ]\n}\n```',
            '- **STIX** returns `application/stix+json;version=2.1` — a STIX 2.1 Bundle of Indicator objects '
              + '(IPv4/IPv6, domain, URL, MD5, SHA-1, SHA-256). Unsupported types are omitted. Disabled STIX is **404**.',
            'For JSON and STIX feeds `?limit=` does not apply (max_items is enforced at generation). ETag / If-None-Match / '
              + 'If-Modified-Since 304 behavior is independent per format.'
          ].join('\n\n'),
          parameters: [
            { name: 'slug', in: 'path', required: true, schema: { type: 'string' } },
            {
              name: 'api_key',
              in: 'query',
              required: true,
              schema: { type: 'string' },
              description: 'Published Feed API key'
            },
            {
              name: 'format',
              in: 'query',
              required: false,
              schema: { type: 'string', enum: ['txt', 'json', 'stix'] },
              description: 'Output format. Default: txt when enabled, else the only enabled format.'
            }
          ],
          responses: {
            '200': {
              description: 'Feed body — text/plain for TXT, application/json for JSON, application/stix+json;version=2.1 for STIX',
              content: {
                'text/plain': { schema: { type: 'string' } },
                'application/stix+json': { schema: { type: 'object' } },
                'application/json': {
                  schema: {
                    type: 'object',
                    required: ['schema_version', 'feed', 'items'],
                    properties: {
                      schema_version: { type: 'string', enum: ['1.0'] },
                      feed: {
                        type: 'object',
                        properties: {
                          name: { type: 'string' },
                          generated_at: { type: 'string', format: 'date-time' },
                          item_count: { type: 'integer' }
                        }
                      },
                      items: {
                        type: 'array',
                        items: {
                          type: 'object',
                          required: ['type', 'value', 'timestamps'],
                          properties: {
                            type: { type: 'string' },
                            value: { type: 'string' },
                            timestamps: { type: 'object' },
                            sources: { type: 'array', items: { type: 'object' } },
                            classification: { type: 'object' },
                            enrichment: { type: 'object' }
                          }
                        }
                      }
                    }
                  }
                }
              }
            },
            '401': { description: 'Invalid API key' },
            '403': { description: 'API key disabled/expired' },
            '404': { description: 'Feed not found' }
          }
        }
      }
    }
  };
}
