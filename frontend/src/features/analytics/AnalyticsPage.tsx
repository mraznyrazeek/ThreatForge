
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
        className="flex min-h-[240px] items-center justify-center gap-3 rounded-lg border border-[#30343F] bg-[#191C24] px-5 py-10"
      >
        <span
          aria-hidden="true"
          className="h-5 w-5 animate-spin rounded-full border-2 border-[#50445F] border-t-[#BAA7E6]"
        />
        <span className="font-mono text-xs text-[#A5A4B1]">
          Loading intelligence analytics...
        </span>
      </div>
    )
  }

  if (error) {
    return (
      <div
        role="alert"
        className="rounded-lg border border-[#69444F] bg-[#251C24] px-5 py-6"
      >
        <p className="text-sm font-semibold text-[#F0ADB9]">
          Analytics unavailable
        </p>
        <p className="mt-2 break-words text-xs leading-6 text-[#C7A7B0]">
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
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="font-mono text-[10px] text-[#9295A3]">
            Intelligence / Analytics
          </p>

          <h1
            id="analytics-heading"
            className="mt-2 text-[25px] font-semibold tracking-[-0.04em] text-[#F1F0F5]"
          >
            Threat Intelligence Analytics
          </h1>

          <p className="mt-1 text-xs text-[#989BA8]">
            Indicator composition, malware intelligence,
            and source activity.
          </p>
        </div>

        <button
          type="button"
          onClick={handleRefresh}
          disabled={loading}
          className="inline-flex h-9 items-center gap-2 rounded-md border border-[#4C455D] bg-[#292435] px-4 text-xs font-medium text-[#D5C8F2] transition-colors hover:border-[#A394CD] hover:bg-[#352E43] disabled:cursor-not-allowed disabled:opacity-50"
        >
          <span aria-hidden="true">↻</span>
          {loading ? 'Loading...' : 'Refresh analytics'}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-3 border-b border-[#30343F] pb-4">
        <span className="inline-flex items-center gap-2 rounded-md border border-[#3A3F4B] bg-[#1A1D25] px-3 py-2 font-mono text-[10px] text-[#B8BBC8]">
          <span className="h-1.5 w-1.5 rounded-full bg-[#72B5A6]" />
          PostgreSQL-backed intelligence
        </span>

        <span className="font-mono text-[10px] text-[#8B909E]">
          Data generated by ThreatForge analytics APIs
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
          <div className="flex flex-wrap items-center justify-between gap-3">
            <span className="font-mono text-[10px] uppercase tracking-wider text-[#999CAC]">
              Malware family ranking
            </span>

            <label className="flex items-center gap-2">
              <span className="text-[11px] text-[#999CAC]">
                Top families
              </span>

              <select
                aria-label="Number of malware families"
                value={familyLimit}
                onChange={(event) =>
                  handleFamilyLimitChange(
                    Number(event.target.value),
                  )
                }
                className="h-8 rounded-md border border-[#414552] bg-[#191C24] px-3 text-xs text-[#E1DCEB] focus:border-[#A999DF] focus:outline-none"
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
              <MalwareFamiliesChart
                data={malware.data}
              />
            )}
          </AnalyticsPanel>
        </div>
      </div>

      <p className="font-mono text-[10px] leading-5 text-[#777D8C]">
        Counts represent observed intelligence records.
        They do not independently establish threat
        severity, confirmed attacks, or incident impact.
      </p>
    </section>
  )
}
