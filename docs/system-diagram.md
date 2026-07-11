# TalonHound System Diagram

## 1) Logical Flow

```mermaid
flowchart LR
    FE[demo-frontend\nUI]
    BE[demo-backend\nAPI]
    R[(demo-redis\nBullMQ queues)]
    IS[demo-integration-scheduler\njob scheduler]
    IW[demo-integration-worker\nIOC import worker]
    EXP[demo-ioc-expiration-worker\nexpiry sweeper]
    DB[(demo-db\nPostgreSQL)]
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

    subgraph HOST[Linux Host 192.168.1.190]
      subgraph COMPOSE[Docker Compose: /opt/TalonHound]
        RP[demo-proxy\n:80 / :443 TLS]
        FE[demo-frontend\n:80 internal]
        BE[demo-backend\n:3000 internal]
        R[(demo-redis)]
        DB[(demo-db\nPostgreSQL)]
        IS[demo-integration-scheduler]
        IW[demo-integration-worker]
        EXP[demo-ioc-expiration-worker]
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
