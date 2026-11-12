
export type Page =
  | 'overview'
  | 'indicators'
  | 'analytics'
  | 'settings'

export type Severity =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'

export interface Indicator {
  id: string
  value: string
  type: string
  source: string
  family: string
  severity: Severity
  detected: string
}
