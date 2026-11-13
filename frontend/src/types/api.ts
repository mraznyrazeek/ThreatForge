
/**
 * ThreatForge ASP.NET Core API contracts.
 *
 * Endpoint:
 * GET /api/v1/intelligence/summary
 *
 * Source:
 * IntelligenceSummaryResponse.cs
 *
 * These interfaces describe actual backend responses,
 * not demonstration dashboard data.
 */

export interface IntelligenceSummaryResponse {
  canonicalIndicators: number
  sourceObservations: number
  intelligenceSources: number
  generatedAtUtc: string
}
