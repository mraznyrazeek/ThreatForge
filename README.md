
# ThreatForge

### Real-Time Cyber Threat Intelligence & Analytics Platform

ThreatForge is a production-oriented cybersecurity
intelligence platform designed to collect, process,
correlate, and analyze security intelligence from
multiple external sources.

## Project Objectives

- Collect real-world cybersecurity threat intelligence.
- Build reliable data engineering pipelines.
- Normalize and correlate threat indicators.
- Analyze software vulnerabilities and exploitation risk.
- Provide interactive threat intelligence dashboards.
- Support security investigations and alerts.
- Demonstrate modern software engineering practices.

## Technology Stack

**Frontend:** React, TypeScript, Vite, Tailwind CSS

**Backend:** C#, ASP.NET Core 10, SignalR

**Data Engineering:** Python, Apache Kafka

**Database:** PostgreSQL

**Infrastructure:** Docker, Azure, GitHub Actions

**Observability:** OpenTelemetry, Grafana

## Initial Data Sources

- ThreatFox
- URLhaus
- AbuseIPDB
- NIST NVD
- CISA KEV
- FIRST EPSS

## Project Status

Milestone 1 — Project Foundation

Architecture and repository initialization.

## Documentation

- [Project Definition](docs/PROJECT_DEFINITION.md)
- [System Architecture](docs/architecture/SYSTEM_ARCHITECTURE.md)

## Development Approach

ThreatForge is developed incrementally, with each
milestone including implementation, validation,
documentation, and version control.

## Security

Threat intelligence is treated as untrusted data.
The platform does not execute malicious payloads.
API credentials and sensitive configurations must
never be committed to version control.
