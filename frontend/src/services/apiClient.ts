
/**
 * ThreatForge authenticated API client.
 *
 * Sends requests through the Vite development proxy.
 * The caller supplies an access-token provider.
 *
 * Access tokens are not persisted in browser storage.
 */

export type AccessTokenProvider = () => Promise<string>

export class ApiError extends Error {
  public readonly status: number

  constructor(status: number, message: string) {
    super(message)

    this.name = 'ApiError'
    this.status = status
  }
}

export async function apiGet<T>(
  path: string,
  getAccessToken: AccessTokenProvider,
  signal?: AbortSignal,
): Promise<T> {
  if (!path.startsWith('/api/')) {
    throw new Error(
      'API requests must use an /api/ path.',
    )
  }

  const token = await getAccessToken()

  const response = await fetch(path, {
    method: 'GET',
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    },
    signal,
    cache: 'no-store',
  })

  if (!response.ok) {
    if (response.status === 401) {
      throw new ApiError(
        401,
        'Your session is unauthorized or has expired.',
      )
    }

    if (response.status === 403) {
      throw new ApiError(
        403,
        'You do not have permission to access this resource.',
      )
    }

    if (response.status === 503) {
      throw new ApiError(
        503,
        'Threat intelligence data is temporarily unavailable.',
      )
    }

    throw new ApiError(
      response.status,
      `API request failed with HTTP ${response.status}.`,
    )
  }

  return (await response.json()) as T
}
