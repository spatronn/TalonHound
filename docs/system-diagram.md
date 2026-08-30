# TalonHound System Diagram

Runtime architecture for the current Compose deployment. Service list: [`docker-compose.yml`](../docker-compose.yml). Operations detail: [container-operations-and-tuning.md](./container-operations-and-tuning.md).

## 1) Logical flow

```mermaid
flowchart LR
    FE[frontend\nUI + API proxy]
    BE[backend\nAPI + published-feed tick]
    R[(redis\nBullMQ)]
    DB[(PostgreSQL)]
    IS[integration-scheduler]
    IW[integration-worker]
    EXP[ioc-expiration-worker]
    ASYNC[export / deep-search /\nbulk-query / backup workers]
    EXT[External IOC feeds\nET / USOM / abuse.ch / …]

    FE -->|/api /public /taxii2| BE
    BE --> DB
    BE -->|enqueue jobs| R
    R --> ASYNC
    ASYNC --> DB

    IS -->|integration-imports| R
    R --> IW
    EXT --> IW
    IW --> DB

    EXP -->|expiry / retention /\nenrichment health probes| DB
    BE -->|Published Feed generation| DB
```

## 2) Deployment view (host + container boundary)

```mermaid
flowchart TB
    IOC[External IOC feeds]
    USER[Analyst browser]

    subgraph HOST[Linux host]
      subgraph COMPOSE[Docker Compose: talonhound]
        RP[proxy\n:80 / :443]
        FE[frontend\n:80 internal]
        BE[backend\n:3000 internal]
        R[(redis)]
        DB[(db\nPostgreSQL)]
        IS[integration-scheduler]
        IW[integration-worker]
        EXP[ioc-expiration-worker]
        EXW[ioc-search-export-worker]
        DSW[ioc-deep-search-worker]
        BQW[ioc-bulk-query-worker]
        BW[backup-worker]
      end
    end

    USER -->|HTTPS :443| RP
    RP --> FE
    FE -->|API| BE
    BE --> DB
    BE --> R
    R --> EXW
    R --> DSW
    R --> BQW
    R --> BW
    EXW --> DB
    DSW --> DB
    BQW --> DB
    BW --> DB

    IS -->|integration-imports| R
    R --> IW
    IOC --> IW
    IW --> DB
    EXP --> DB
```

Host-published ports: **80** and **443** on `proxy` only.
