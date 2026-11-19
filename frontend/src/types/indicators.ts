
/**
 * ThreatForge indicator API response contracts.
 *
 * Backend:
 * Models/PagedIndicatorsResponse.cs
 *
 * Endpoint:
 * GET /api/v1/intelligence/indicators
 */

export interface IndicatorListItem {
  id: number
  indicatorType: string
  normalizedValue: string
  observationCount: number
  createdAtUtc: string
}

export interface PagedIndicatorsResponse {
  items: IndicatorListItem[]
  page: number
  pageSize: number
  totalItems: number
  totalPages: number
  hasNextPage: boolean
  hasPreviousPage: boolean
}

export interface IndicatorQueryParams {
  page: number
  pageSize: number
  indicatorType?: string
}
