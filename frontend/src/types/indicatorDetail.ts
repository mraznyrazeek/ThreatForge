
export interface IndicatorObservation {
  id: number
  sourceId: number
  sourceName: string
  sourceRecordId: string
  threatType: string
  malwareFamily: string | null
  confidenceLevel: number
  firstSeenUtc: string
  lastSeenUtc: string | null
  timestampQuality: string
  reporter: string | null
  reference: string | null
  tags: unknown
  updatedAtUtc: string
}

export interface IndicatorDetailResponse {
  id: number
  indicatorType: string
  normalizedValue: string
  createdAtUtc: string
  observationCount: number
  hasMoreObservations: boolean
  observations: IndicatorObservation[]
}
