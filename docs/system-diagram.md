# TalonHound System Diagram

## 1) Logical Flow

```mermaid
flowchart LR
    FE[frontend\nUI]
    BE[backend\nAPI]
    R[(redis\nBullMQ queues)]
    IS[integration-scheduler\njob scheduler]
    IW[integration-worker\nIOC import worker]
    EXP[ioc-expiration-worker\nexpiry sweeper]
    DB[(db\nPostgreSQL)]
    EXT[(IOC Feeds\nET / USOM / URLhaus)]

    FE -->|API calls| BE
    BE -->|queries| DB

    IS -->|enqueue integration-imports| R
    R -->|consume integration-imports| IW
    EXT -->|fetch IOC lists| IW
    IW -->|upsert ioc_items| DB

    EXP -->|expire stale IOCs| DB
```

## 2) Deployment View (Host + Container Boundary)

```mermaid
flowchart TB
    IOC[External IOC Feeds\nET / USOM / URLhaus]

    subgraph HOST[Linux Host]
      subgraph COMPOSE[Docker Compose: /opt/TalonHound]
        RP[proxy\n:80 / :443 TLS]
        FE[frontend\n:80 internal]
        BE[backend\n:3000 internal]
        R[(redis)]
        DB[(db\nPostgreSQL)]
        IS[integration-scheduler]
        IW[integration-worker]
        EXP[ioc-expiration-worker]
      end
    end

    USER[Analyst Browser] -->|HTTPS :443| RP
    RP --> FE
    FE -->|API| BE
    BE --> DB

    IS -->|integration-imports| R
    R --> IW
    IOC --> IW
    IW --> DB

    EXP --> DB
```
