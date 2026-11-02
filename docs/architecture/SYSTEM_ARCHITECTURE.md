
# ThreatForge — System Architecture

**Version:** 1.0  
**Status:** Initial Architecture Design

## 1. System Overview

ThreatForge is a modular, event-driven cybersecurity
threat intelligence and analytics platform.

The system collects cybersecurity intelligence from
external APIs, processes and normalizes the data,
correlates threat indicators, and provides analytical
insights through a web application.

## 2. Architectural Principles

- Modular service architecture
- Separation of concerns
- API-first backend development
- Event-driven data processing
- Reliable and idempotent ingestion
- Secure credential management
- Observability and testability
- Incremental infrastructure adoption

## 3. Primary System Components

### 3.1 Data Ingestion Layer

Technology: Python

Responsibilities:
- Connect to external cybersecurity intelligence APIs
- Authenticate with supported providers
- Retrieve new and updated threat information
- Respect API rate limits
- Implement retries and error handling
- Record ingestion checkpoints and metadata

Initial integrations:
- ThreatFox
- URLhaus

Planned integrations:
- AbuseIPDB
- NIST NVD
- CISA KEV
- FIRST EPSS

### 3.2 Event Streaming Layer

Technology: Apache Kafka

Responsibilities:
- Buffer incoming threat intelligence events
- Decouple ingestion from processing
- Support consumer-based processing
- Allow controlled event replay
- Support retry and dead-letter workflows

Kafka will be introduced after initial ingestion
and database persistence are validated.

### 3.3 Data Processing Layer

Technology: Python

Responsibilities:
- Validate incoming records
- Normalize indicator formats
- Deduplicate records
- Preserve source provenance
- Enrich threat information
- Calculate explainable priority scores
- Record processing errors

### 3.4 Persistence Layer

Primary database: PostgreSQL

Responsibilities:
- Store normalized threat indicators
- Store vulnerability intelligence
- Maintain source observations
- Track historical changes
- Record alerts and investigations
- Persist ingestion and processing metadata

Future supporting components:
- Redis for caching
- OpenSearch for advanced searching

### 3.5 Backend Application Layer

Technology: ASP.NET Core 10 / C#

Responsibilities:
- Expose REST APIs
- Implement authentication and authorization
- Manage investigations and alerts
- Provide intelligence search and filtering
- Expose analytical summaries
- Deliver real-time notifications through SignalR

### 3.6 Frontend Application Layer

Technology:
- React
- TypeScript
- Vite
- Tailwind CSS

Responsibilities:
- Threat intelligence dashboard
- Threat indicator explorer
- Vulnerability intelligence
- Security investigation views
- Alert management
- Data pipeline health monitoring

## 4. High-Level Data Flow

External Intelligence APIs
    |
    v
Python Ingestion Services
    |
    v
Apache Kafka (planned)
    |
    v
Python Processing Services
    |
    v
PostgreSQL
    |
    v
ASP.NET Core REST API
    |
    v
React Dashboard

Initial implementation will persist collected
records without Kafka. Streaming will be added
as a subsequent milestone.

## 5. Security Principles

- Never commit API keys or credentials
- Treat external source data as untrusted
- Avoid executing or accessing malicious payloads
- Preserve original evidence and attribution
- Validate all API inputs
- Apply least-privilege access
- Record security-sensitive application actions

## 6. Development Infrastructure

Development environment:
- macOS
- Visual Studio Code
- Docker and Docker Compose
- Git and GitHub

Planned cloud environment:
- Microsoft Azure

## 7. Testing Strategy

- Python unit tests with pytest
- Backend unit tests with xUnit
- Integration tests for data persistence
- API contract testing
- Frontend component testing
- End-to-end testing with Playwright

## 8. Engineering Approach

ThreatForge will be developed incrementally.

Each milestone must include:
1. Implementation
2. Validation
3. Relevant automated testing
4. Documentation updates
5. Git review and commit

Architecture changes will be documented
before introducing significant new components.
