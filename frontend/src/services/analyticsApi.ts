
import { apiGet } from './apiClient'

import type {
  IndicatorDistributionResponse,
  MalwareFamilyResponse,
  DailyThreatActivityResponse,
} from '../types/analytics'

type AccessTokenProvider = () => Promise<string>

export async function getIndicatorDistribution(
  getAccessToken: AccessTokenProvider,
  signal?: AbortSignal,
): Promise<IndicatorDistributionResponse> {
  return apiGet<IndicatorDistributionResponse>(
    '/api/v1/analytics/indicators/distribution',
    getAccessToken,
    signal,
  )
}

/**
 * GET /api/v1/analytics/malware/families
 *
 * Retrieves the most frequently observed
 * malware families.
 *
 * Valid limit: 1–100.
 */
export async function getMalwareFamilies(
  getAccessToken: AccessTokenProvider,
  limit = 15,
  signal?: AbortSignal,
): Promise<MalwareFamilyResponse> {
  if (
    !Number.isInteger(limit) ||
    limit < 1 ||
    limit > 100
  ) {
    throw new Error(
      'Malware family limit must be between 1 and 100.',
    )
  }

  const query = new URLSearchParams({
    limit: String(limit),
  })

  return apiGet<MalwareFamilyResponse>(
    `/api/v1/analytics/malware/families?${query.toString()}`,
    getAccessToken,
    signal,
  )
}

/**
 * GET /api/v1/analytics/temporal/daily
 *
 * Retrieves daily threat activity grouped
 * by date and intelligence source.
 */
export async function getDailyThreatActivity(
  getAccessToken: AccessTokenProvider,
  signal?: AbortSignal,
): Promise<DailyThreatActivityResponse> {
  return apiGet<DailyThreatActivityResponse>(
    '/api/v1/analytics/temporal/daily',
    getAccessToken,
    signal,
  )
}
