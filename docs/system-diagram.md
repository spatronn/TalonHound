# Demo-Run System Diagram

## 1) Logical Flow

```mermaid
flowchart LR
    FE[demo-frontend\nUI]
    BE[demo-backend\nAPI + enqueue]
    R[(demo-redis\nBullMQ queues)]
    SE[demo-signal-engine\nqueue consumer]
    IS[demo-integration-scheduler\njob scheduler]
    IW[demo-integration-worker\nIOC import worker]
    DB[(demo-db\nPostgreSQL)]
    EXT[(IOC Feeds\nET / USOM / URLhaus)]

    FE -->|API calls| BE

    BE -->|enqueue signal-events| R
    R -->|consume signal-events| SE
    SE -->|write raw events + ioc_match_events| DB

    IS -->|enqueue integration-imports| R
    R -->|consume integration-imports| IW
    EXT -->|fetch IOC lists| IW
    IW -->|upsert ioc_items| DB

    BE -->|analytics/auth queries| DB
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
        SE[demo-signal-engine]
        IS[demo-integration-scheduler]
        IW[demo-integration-worker]
        LLMW[demo-llm-risk-worker]
        SR[demo-syslog-receiver\n:514 UDP]
      end
    end

    USER[Analyst Browser] -->|HTTPS :443| RP
    RP --> FE
    FE -->|API| BE

    BE -->|signal-events| R
    BE -->|llm-risk-jobs| R
    R --> SE
    R --> LLMW
    SE --> DB

    IS -->|integration-imports| R
    R --> IW
    IOC --> IW
    IW --> DB

    SR --> DB
    BE --> DB
```
