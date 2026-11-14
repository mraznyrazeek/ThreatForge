
export type AppPage =
  | 'overview'
  | 'indicators'
  | 'analytics'

export const PAGE_TITLES: Record<AppPage, string> = {
  overview: 'Overview',
  indicators: 'Threat Indicators',
  analytics: 'Threat Analytics',
}
