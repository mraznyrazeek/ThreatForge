
import {
  apiGet,
  type AccessTokenProvider,
} from './apiClient'

import type {
  IntelligenceSummaryResponse,
} from '../types/api'

const INTELLIGENCE_SUMMARY_ENDPOINT =
  '/api/v1/intelligence/summary'

/**
 * Retrieve the current intelligence summary from
 * the protected ThreatForge ASP.NET Core API.
 *
 * Authentication:
 * Keycloak JWT Bearer token.
 *
 * Data source:
 * PostgreSQL, through the backend summary service.
 */
export async function getIntelligenceSummary(
  getAccessToken: AccessTokenProvider,
  signal?: AbortSignal,
): Promise<IntelligenceSummaryResponse> {
  return apiGet<IntelligenceSummaryResponse>(
    INTELLIGENCE_SUMMARY_ENDPOINT,
    getAccessToken,
    signal,
  )
}
