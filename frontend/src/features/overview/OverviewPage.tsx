
import { useCallback, useEffect, useState } from 'react'

import { useAuth } from '../../auth/useAuth'
import { getIntelligenceSummary } from '../../services/intelligenceApi'
import type { IntelligenceSummaryResponse } from '../../types/api'

type MetricTone = 'emerald' | 'cyan' | 'amber'

interface Metric {
  label: string
  value: number
  description: string
  code: string
  tone: MetricTone
}

const metricStyles: Record<
  MetricTone,
  {
    border: string
    text: string
    glow: string
    bar: string
  }
> = {
  emerald: {
    border: 'border-[#2D6956]',
    text: 'text-[#70EFC0]',
    glow: 'bg-[#51E9B5]',
    bar: 'bg-[#51E9B5]',
  },
  cyan: {
    border: 'border-[#326778]',
    text: 'text-[#70DDEA]',
    glow: 'bg-[#61D8EB]',
    bar: 'bg-[#61D8EB]',
  },
  amber: {
    border: 'border-[#745B3B]',
    text: 'text-[#F0C183]',
    glow: 'bg-[#F3B66A]',
    bar: 'bg-[#F3B66A]',
  },
}

function AnimatedNumber({ value }: { value: number }) {
  const [display, setDisplay] = useState(0)

  const reducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)')
      .matches

  useEffect(() => {
    if (reducedMotion) return

    let animationFrame = 0
    let startTime: number | null = null
    const duration = 550

    const animate = (timestamp: number) => {
      if (startTime === null) {
        startTime = timestamp
      }

      const progress = Math.min(
        (timestamp - startTime) / duration,
        1,
      )

      const eased = 1 - Math.pow(1 - progress, 3)

      setDisplay(Math.round(value * eased))

      if (progress < 1) {
        animationFrame = requestAnimationFrame(animate)
      }
    }

    animationFrame = requestAnimationFrame(animate)

    return () => {
      cancelAnimationFrame(animationFrame)
    }
  }, [value, reducedMotion])

  return (
    <span className="tabular-nums">
      {(reducedMotion ? value : display).toLocaleString()}
    </span>
  )
}

function MetricCard({ metric }: { metric: Metric }) {
  const style = metricStyles[metric.tone]

  return (
    <article
      className={`tf-glow-border relative overflow-hidden rounded border bg-[#101A1D] px-5 py-5 ${style.border}`}
    >
      <div
        aria-hidden="true"
        className={`absolute left-0 top-0 h-[2px] w-24 ${style.bar}`}
      />

      <div
        aria-hidden="true"
        className={`absolute -right-10 -top-12 h-32 w-32 rounded-full opacity-[0.055] blur-3xl ${style.glow}`}
      />

      <div className="relative">
        <div className="flex items-center justify-between gap-3">
          <span className="font-mono text-[10px] tracking-[0.13em] text-[#92B7AB]">
            {metric.label}
          </span>

          <span className={`font-mono text-[10px] ${style.text}`}>
            {metric.code}
          </span>
        </div>

        <div
          className={`mt-6 font-mono text-[clamp(1.9rem,3vw,2.7rem)] font-semibold leading-none tracking-[-0.06em] ${style.text}`}
        >
          <AnimatedNumber value={metric.value} />
        </div>

        <p className="mt-3 text-[11px] text-[#89A79C]">
          {metric.description}
        </p>

        <div className="mt-5 flex items-center gap-2">
          <div className={`h-[2px] w-10 ${style.bar}`} />

          <div className="h-px flex-1 bg-[#29453D]" />
        </div>
      </div>
    </article>
  )
}

function SnapshotPanel({
  summary,
}: {
  summary: IntelligenceSummaryResponse
}) {
  const observedAt = new Date(summary.generatedAtUtc)
  const validDate = !Number.isNaN(observedAt.getTime())

  return (
    <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
      <section className="tf-panel tf-glow-border rounded">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#263E38] px-5 py-4">
          <div>
            <p className="tf-terminal-label">
              // INTELLIGENCE STRUCTURE
            </p>

            <h2 className="mt-1 text-[14px] font-semibold text-[#DFF8EC]">
              Threat intelligence inventory
            </h2>
          </div>

          <span className="rounded border border-[#2F5849] bg-[#122920] px-2 py-1 font-mono text-[9px] text-[#7BDCB1]">
            DATABASE SNAPSHOT
          </span>
        </div>

        <div className="grid gap-3 p-5 sm:grid-cols-3">
          <div className="rounded border border-[#315A4B] bg-[#10241D] p-4">
            <span className="font-mono text-[9px] tracking-wider text-[#7CC7A9]">
              01 / SOURCES
            </span>

            <p className="mt-3 font-mono text-2xl font-semibold text-[#8FF4C9]">
              {summary.intelligenceSources.toLocaleString()}
            </p>

            <p className="mt-2 text-[11px] text-[#93B4A6]">
              Contributing intelligence feeds
            </p>
          </div>

          <div className="rounded border border-[#315968] bg-[#102127] p-4">
            <span className="font-mono text-[9px] tracking-wider text-[#80CBD9]">
              02 / OBSERVATIONS
            </span>

            <p className="mt-3 font-mono text-2xl font-semibold text-[#8BE9F5]">
              {summary.sourceObservations.toLocaleString()}
            </p>

            <p className="mt-2 text-[11px] text-[#97B6BB]">
              Source-specific intelligence
            </p>
          </div>

          <div className="rounded border border-[#675536] bg-[#231E16] p-4">
            <span className="font-mono text-[9px] tracking-wider text-[#D9B27A]">
              03 / INDICATORS
            </span>

            <p className="mt-3 font-mono text-2xl font-semibold text-[#F1C98E]">
              {summary.canonicalIndicators.toLocaleString()}
            </p>

            <p className="mt-2 text-[11px] text-[#C0AB8A]">
              Deduplicated canonical IOCs
            </p>
          </div>
        </div>

        <p className="border-t border-[#263E38] px-5 py-3 font-mono text-[10px] leading-relaxed text-[#76988C]">
          Sources → Source observations → Canonical indicators
        </p>
      </section>

      <section className="tf-panel tf-glow-border rounded">
        <div className="border-b border-[#263E38] px-5 py-4">
          <p className="tf-terminal-label">
            // SNAPSHOT METADATA
          </p>

          <h2 className="mt-1 text-[14px] font-semibold text-[#DFF8EC]">
            Intelligence connection
          </h2>
        </div>

        <div className="space-y-5 p-5">
          <div>
            <p className="font-mono text-[9px] tracking-wider text-[#76998D]">
              RESPONSE SOURCE
            </p>

            <p className="mt-2 font-mono text-xs text-[#C4E7D9]">
              SECURED INTELLIGENCE API
            </p>
          </div>

          <div className="h-px bg-[#263E38]" />

          <div>
            <p className="font-mono text-[9px] tracking-wider text-[#76998D]">
              SNAPSHOT GENERATED
            </p>

            <p className="mt-2 font-mono text-xs text-[#B5D9CC]">
              {validDate
                ? observedAt.toLocaleString()
                : 'Timestamp unavailable'}
            </p>
          </div>

          <div className="h-px bg-[#263E38]" />

          <p className="text-[11px] leading-relaxed text-[#829F94]">
            Metrics represent the latest successfully
            retrieved intelligence inventory snapshot.
            They are not live event-stream counters.
          </p>
        </div>
      </section>
    </div>
  )
}

export function OverviewPage() {
  const { getAccessToken } = useAuth()

  const [summary, setSummary] =
    useState<IntelligenceSummaryResponse | null>(null)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getIntelligenceSummary(
      getAccessToken,
      controller.signal,
    )
      .then((result) => {
        if (!active) return

        setSummary(result)
        setError(null)
        setLoading(false)
      })
      .catch((requestError: unknown) => {
        if (!active || controller.signal.aborted) return

        setError(
          requestError instanceof Error
            ? requestError.message
            : 'Unable to load intelligence.',
        )

        setLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [getAccessToken, refreshKey])

  const refresh = useCallback(() => {
    setLoading(true)
    setError(null)
    setRefreshKey((previous) => previous + 1)
  }, [])

  const metrics: Metric[] = summary
    ? [
        {
          label: 'CANONICAL INDICATORS',
          value: summary.canonicalIndicators,
          description: 'Unique normalized indicators',
          code: 'IOC_01',
          tone: 'emerald',
        },
        {
          label: 'SOURCE OBSERVATIONS',
          value: summary.sourceObservations,
          description: 'Current source observation records',
          code: 'OBS_02',
          tone: 'cyan',
        },
        {
          label: 'INTELLIGENCE SOURCES',
          value: summary.intelligenceSources,
          description: 'Contributing intelligence feeds',
          code: 'SRC_03',
          tone: 'amber',
        },
      ]
    : []

  return (
    <section
      aria-labelledby="overview-heading"
      className="space-y-5"
    >
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[#29473D] pb-5">
        <div>
          <p className="font-mono text-[10px] tracking-wide text-[#79BA9D]">
            THREATFORGE / INTELLIGENCE / OVERVIEW
          </p>

          <div className="mt-3 flex items-center gap-3">
            <span
              aria-hidden="true"
              className="h-7 w-[3px] rounded bg-[#51E9B5] shadow-[0_0_12px_rgba(81,233,181,0.3)]"
            />

            <h1
              id="overview-heading"
              className="text-[clamp(1.5rem,3vw,2rem)] font-semibold tracking-[-0.045em] text-[#E8FFF5]"
            >
              System Overview
            </h1>
          </div>

          <p className="mt-2 text-xs text-[#8BAA9E]">
            Threat intelligence inventory and collection snapshot
          </p>
        </div>

        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="inline-flex h-9 items-center gap-2 rounded border border-[#398064] bg-[#143126] px-4 font-mono text-[10px] font-medium tracking-wide text-[#A2F1D0] transition-colors hover:border-[#6CE8B6] hover:bg-[#1B4433] disabled:opacity-50"
        >
          <span aria-hidden="true">↻</span>

          {loading ? 'UPDATING' : 'REFRESH DATA'}
        </button>
      </div>

      {loading && !summary && (
        <div
          role="status"
          className="grid gap-3 md:grid-cols-3"
        >
          {Array.from({ length: 3 }).map((_, index) => (
            <div
              key={index}
              className="animate-pulse rounded border border-[#2C5447] bg-[#101A1D] p-5"
            >
              <div className="h-3 w-32 rounded bg-[#294C40]" />

              <div className="mt-6 h-10 w-36 rounded bg-[#1C3C33]" />

              <div className="mt-4 h-2 w-40 rounded bg-[#1A342D]" />
            </div>
          ))}

          <span className="sr-only">
            Loading intelligence summary
          </span>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="rounded border border-[#794447] bg-[#2A191C] px-4 py-3 text-xs text-[#FFAAAA]"
        >
          Unable to retrieve intelligence: {error}
        </div>
      )}

      {summary && (
        <>
          <div className="grid gap-3 md:grid-cols-3">
            {metrics.map((metric) => (
              <MetricCard
                key={metric.label}
                metric={metric}
              />
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-[#27453B] bg-[#0D1B1A] px-4 py-3">
            <div className="flex items-center gap-2">
              <span
                aria-hidden="true"
                className={`h-1.5 w-1.5 rounded-full ${
                  error
                    ? 'bg-[#FF777E]'
                    : loading
                      ? 'animate-pulse bg-[#F3B66A]'
                      : 'bg-[#51E9B5] shadow-[0_0_8px_rgba(81,233,181,0.5)]'
                }`}
              />

              <span className="font-mono text-[10px] text-[#9AD6BF]">
                {error
                  ? 'LAST SUCCESSFUL SNAPSHOT'
                  : loading
                    ? 'UPDATING INVENTORY'
                    : 'API CONNECTED'}
              </span>
            </div>

            <span className="font-mono text-[10px] text-[#779B8F]">
              GENERATED{' '}
              {new Date(
                summary.generatedAtUtc,
              ).toLocaleString()}
            </span>
          </div>

          <SnapshotPanel summary={summary} />
        </>
      )}
    </section>
  )
}
