
// ------------------------------------
// Indicator distribution
// ------------------------------------

export interface IndicatorDistributionItem {
  indicatorType: string
  count: number
  percentage: number
}

export interface IndicatorDistributionResponse {
  totalIndicators: number
  distribution: IndicatorDistributionItem[]
  generatedAtUtc: string
}

// ------------------------------------
// Malware family analytics
// ------------------------------------

export interface MalwareFamilyItem {
  malwareFamily: string
  observationCount: number
  distinctIndicatorCount: number
}

export interface MalwareFamilyResponse {
  limit: number
  families: MalwareFamilyItem[]
  generatedAtUtc: string
}

// ------------------------------------
// Daily threat activity
// ------------------------------------

export interface DailyThreatActivityItem {
  dateUtc: string
  sourceName: string
  observationCount: number
  distinctIndicatorCount: number
}

export interface DailyThreatActivityResponse {
  timezone: string
  totalObservations: number
  dailyActivity: DailyThreatActivityItem[]
  generatedAtUtc: string
}
