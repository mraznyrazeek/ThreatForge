
import { useEffect, useState } from 'react'

import { useAuth } from '../../auth/useAuth'

import {
  getIndicatorDistribution,
  getMalwareFamilies,
  getDailyThreatActivity,
} from '../../services/analyticsApi'

import type {
  IndicatorDistributionResponse,
  MalwareFamilyResponse,
  DailyThreatActivityResponse,
} from '../../types/analytics'

import { IndicatorDistributionChart } from './IndicatorDistributionChart'
import { MalwareFamiliesChart } from './MalwareFamiliesChart'
import { DailyActivityChart } from './DailyActivityChart'

type RequestState<T> = {
  data: T | null
  error: string | null
  loading: boolean
}

function initialState<T>(): RequestState<T> {
  return {
    data: null,
    error: null,
    loading: true,
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : 'Unable to retrieve analytics data.'
}

interface AnalyticsPanelProps {
  loading: boolean
  error: string | null
  children: React.ReactNode
}

function AnalyticsPanel({
  loading,
  error,
  children,
}: AnalyticsPanelProps) {
  if (loading) {
    return (
      <div
        role="status"
        className="flex min-h-[240px] items-center justify-center gap-3 rounded border border-[#2C5246] bg-[#101A1D] px-5 py-10"
      >
        <span
          aria-hidden="true"
          className="h-5 w-5 animate-spin rounded-full border-2 border-[#31594C] border-t-[#51E9B5]"
        />

        <span className="font-mono text-xs text-[#9EDAC1]">
          RETRIEVING ANALYTICS DATA...
        </span>
      </div>
    )
  }

  if (error) {
    return (
      <div
        role="alert"
        className="rounded border border-[#794447] bg-[#2A191C] px-5 py-6"
      >
        <p className="font-mono text-xs font-semibold text-[#FFAAAA]">
          ANALYTICS UNAVAILABLE
        </p>

        <p className="mt-2 break-words text-xs leading-6 text-[#E2A4A8]">
          {error}
        </p>
      </div>
    )
  }

  return <>{children}</>
}

export function AnalyticsPage() {
  const { getAccessToken } = useAuth()

  const [distribution, setDistribution] = useState<
    RequestState<IndicatorDistributionResponse>
  >(initialState)

  const [malware, setMalware] = useState<
    RequestState<MalwareFamilyResponse>
  >(initialState)

  const [daily, setDaily] = useState<
    RequestState<DailyThreatActivityResponse>
  >(initialState)

  const [familyLimit, setFamilyLimit] = useState(15)
  const [refreshKey, setRefreshKey] = useState(0)

  // Distribution and activity do not depend on familyLimit.
  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getIndicatorDistribution(
      getAccessToken,
      controller.signal,
    )
      .then((data) => {
        if (!active) return
        setDistribution({
          data,
          error: null,
          loading: false,
        })
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return
        setDistribution({
          data: null,
          error: errorMessage(error),
          loading: false,
        })
      })

    getDailyThreatActivity(
      getAccessToken,
      controller.signal,
    )
      .then((data) => {
        if (!active) return
        setDaily({
          data,
          error: null,
          loading: false,
        })
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return
        setDaily({
          data: null,
          error: errorMessage(error),
          loading: false,
        })
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [getAccessToken, refreshKey])

  // Ranking requests change independently of the other charts.
  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getMalwareFamilies(
      getAccessToken,
      familyLimit,
      controller.signal,
    )
      .then((data) => {
        if (!active) return
        setMalware({
          data,
          error: null,
          loading: false,
        })
      })
      .catch((error: unknown) => {
        if (!active || controller.signal.aborted) return
        setMalware({
          data: null,
          error: errorMessage(error),
          loading: false,
        })
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [getAccessToken, familyLimit, refreshKey])

  function handleRefresh() {
    setDistribution(initialState())
    setMalware(initialState())
    setDaily(initialState())
    setRefreshKey((value) => value + 1)
  }

  function handleFamilyLimitChange(value: number) {
    if (value === familyLimit) return

    setMalware(initialState())
    setFamilyLimit(value)
  }

  const loading =
    distribution.loading ||
    malware.loading ||
    daily.loading

  return (
    <section
      aria-labelledby="analytics-heading"
      className="space-y-5"
    >
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[#29473D] pb-5">
        <div>
          <p className="font-mono text-[10px] tracking-wide text-[#79BA9D]">
            THREATFORGE / INTELLIGENCE / ANALYTICS
          </p>

          <div className="mt-3 flex items-center gap-3">
            <span
              aria-hidden="true"
              className="h-7 w-[3px] rounded bg-[#51E9B5] shadow-[0_0_12px_rgba(81,233,181,0.3)]"
            />

            <h1
              id="analytics-heading"
              className="text-[clamp(1.5rem,3vw,2rem)] font-semibold tracking-[-0.045em] text-[#E8FFF5]"
            >
              Threat Intelligence Analytics
            </h1>
          </div>

          <p className="mt-2 text-xs text-[#8BAA9E]">
            Indicator composition, malware intelligence, and
            source activity
          </p>
        </div>

        <button
          type="button"
          onClick={handleRefresh}
          disabled={loading}
          className="inline-flex h-9 items-center gap-2 rounded border border-[#398064] bg-[#143126] px-4 font-mono text-[10px] font-medium tracking-wide text-[#A2F1D0] transition-colors hover:border-[#6CE8B6] hover:bg-[#1B4433] disabled:opacity-50"
        >
          <span aria-hidden="true">↻</span>
          {loading ? 'UPDATING' : 'REFRESH ANALYTICS'}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 rounded border border-[#274D40] bg-[#0D1B1A] px-4 py-3">
        <span className="tf-status-dot" />

        <span className="font-mono text-[10px] tracking-wide text-[#A2DBC0]">
          POSTGRESQL-BACKED INTELLIGENCE
        </span>

        <span className="hidden h-4 w-px bg-[#315346] sm:block" />

        <span className="font-mono text-[10px] text-[#719C8B]">
          DATA SOURCE: THREATFORGE ANALYTICS API
        </span>
      </div>

      <AnalyticsPanel
        loading={daily.loading}
        error={daily.error}
      >
        {daily.data && (
          <DailyActivityChart data={daily.data} />
        )}
      </AnalyticsPanel>

      <div className="grid items-start gap-5 2xl:grid-cols-2">
        <AnalyticsPanel
          loading={distribution.loading}
          error={distribution.error}
        >
          {distribution.data && (
            <IndicatorDistributionChart
              data={distribution.data}
            />
          )}
        </AnalyticsPanel>

        <div className="min-w-0 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-[#2C5246] bg-[#0D1A1B] px-4 py-3">
            <span className="font-mono text-[10px] font-medium tracking-wider text-[#A4E7C8]">
              // MALWARE FAMILY RANKING
            </span>

            <label className="flex items-center gap-2">
              <span className="font-mono text-[10px] text-[#83B6A4]">
                TOP FAMILIES
              </span>

              <select
                aria-label="Number of malware families"
                value={familyLimit}
                disabled={malware.loading}
                onChange={(event) =>
                  handleFamilyLimitChange(
                    Number(event.target.value),
                  )
                }
                className="h-8 rounded border border-[#356450] bg-[#091713] px-3 font-mono text-[11px] text-[#C5F4DB] focus:border-[#51E9B5] focus:outline-none"
              >
                <option value={5}>5</option>
                <option value={10}>10</option>
                <option value={15}>15</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
              </select>
            </label>
          </div>

          <AnalyticsPanel
            loading={malware.loading}
            error={malware.error}
          >
            {malware.data && (
              <MalwareFamiliesChart data={malware.data} />
            )}
          </AnalyticsPanel>
        </div>
      </div>

      <p className="border-t border-[#29473D] pt-4 font-mono text-[10px] leading-6 text-[#779B8F]">
        ANALYTICAL NOTE — Counts represent observed intelligence
        records. They do not independently establish threat
        severity, confirmed attacks, or incident impact.
      </p>
    </section>
  )
}
