
import {
  apiGet,
  type AccessTokenProvider,
} from './apiClient'

import type {
  IndicatorQueryParams,
  PagedIndicatorsResponse,
} from '../types/indicators'

import type {
  IndicatorDetailResponse,
} from '../types/indicatorDetail'

const INDICATORS_ENDPOINT =
  '/api/v1/intelligence/indicators'

const MAX_SEARCH_LENGTH = 256
const MAX_TYPE_LENGTH = 64

/**
 * Retrieve paginated threat indicators from PostgreSQL
 * through the secured ASP.NET Core API.
 *
 * Authentication:
 * Keycloak Bearer JWT
 *
 * Supported query parameters:
 * - page
 * - pageSize
 * - type
 * - search
 *
 * Search uses server-side, case-insensitive,
 * literal substring matching.
 */
export async function getThreatIndicators(
  getAccessToken: AccessTokenProvider,
  params: IndicatorQueryParams,
  signal?: AbortSignal,
): Promise<PagedIndicatorsResponse> {
  const {
    page,
    pageSize,
    indicatorType,
    search,
  } = params

  if (!Number.isInteger(page) || page < 1) {
    throw new Error(
      'Page must be a positive integer.',
    )
  }

  if (
    !Number.isInteger(pageSize) ||
    pageSize < 1 ||
    pageSize > 100
  ) {
    throw new Error(
      'Page size must be an integer between 1 and 100.',
    )
  }

  if (
    indicatorType !== undefined &&
    indicatorType.length > MAX_TYPE_LENGTH
  ) {
    throw new Error(
      'Indicator type must not exceed 64 characters.',
    )
  }

  if (
    search !== undefined &&
    search.length > MAX_SEARCH_LENGTH
  ) {
    throw new Error(
      'IOC search must not exceed 256 characters.',
    )
  }

  const query = new URLSearchParams({
    page: String(page),
    pageSize: String(pageSize),
  })

  const normalizedType = indicatorType?.trim()
  const normalizedSearch = search?.trim()

  if (normalizedType) {
    query.set('type', normalizedType)
  }

  if (normalizedSearch) {
    query.set('search', normalizedSearch)
  }

  return apiGet<PagedIndicatorsResponse>(
    `${INDICATORS_ENDPOINT}?${query.toString()}`,
    getAccessToken,
    signal,
  )
}

/**
 * Retrieve one canonical threat indicator together
 * with its latest source-specific observations.
 *
 * Uses the same Keycloak-authenticated API client.
 *
 * The backend currently returns up to 100 current
 * observation records and indicates whether more exist.
 */
export async function getThreatIndicatorDetail(
  getAccessToken: AccessTokenProvider,
  indicatorId: number,
  signal?: AbortSignal,
): Promise<IndicatorDetailResponse> {
  if (
    !Number.isSafeInteger(indicatorId) ||
    indicatorId < 1
  ) {
    throw new Error(
      'Indicator ID must be a positive safe integer.',
    )
  }

  return apiGet<IndicatorDetailResponse>(
    `${INDICATORS_ENDPOINT}/${indicatorId}`,
    getAccessToken,
    signal,
  )
}
