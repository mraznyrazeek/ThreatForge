
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../../auth/useAuth'
import { getIntelligenceSummary } from '../../services/intelligenceApi'
import type { IntelligenceSummaryResponse } from '../../types/api'

interface Metric {
  label: string
  value: number
  description: string
}

function AnimatedNumber({ value }: { value: number }) {
  const [display, setDisplay] = useState(0)

  const reducedMotion =
    typeof window !== 'undefined' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches

  useEffect(() => {
    if (reducedMotion) {
      return
    }

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
  return (
    <article className="rounded-md border border-[#30343f] bg-[#191c24] px-5 py-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-mono text-[10px] font-medium uppercase tracking-[0.09em] text-[#969baa]">
          {metric.label}
        </h3>

        <span
          className="h-1.5 w-1.5 rounded-full bg-[#a69acb]"
          aria-hidden="true"
        />
      </div>

      <div className="mt-4 text-[clamp(1.8rem,3vw,2.5rem)] font-semibold leading-none tracking-[-0.045em] text-[#f0eff4]">
        <AnimatedNumber value={metric.value} />
      </div>

      <p className="mt-3 text-[11px] text-[#858c9a]">
        {metric.description}
      </p>
    </article>
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
          label: 'Canonical Indicators',
          value: summary.canonicalIndicators,
          description: 'Unique normalized indicators',
        },
        {
          label: 'Source Observations',
          value: summary.sourceObservations,
          description: 'Collected threat observations',
        },
        {
          label: 'Intelligence Sources',
          value: summary.intelligenceSources,
          description: 'Contributing intelligence feeds',
        },
      ]
    : []

  return (
    <section aria-labelledby="overview-heading">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 font-mono text-[10px] text-[#898e9c]">
            <span>Intelligence</span>
            <span className="text-[#595e6c]">/</span>
            <span className="text-[#b9afd9]">Overview</span>
          </div>

          <h1
            id="overview-heading"
            className="mt-2 text-[25px] font-semibold tracking-[-0.045em] text-[#f2f1f5]"
          >
            Overview
          </h1>

          <p className="mt-1 text-xs text-[#8a909e]">
            Intelligence inventory
          </p>
        </div>

        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="rounded-md border border-[#454251] bg-[#211f2b] px-4 py-2 text-xs font-medium text-[#c5b9e4] transition-colors hover:border-[#8e82bf] hover:bg-[#2a2636] disabled:opacity-50"
        >
          {loading ? 'Updating...' : '↻ Refresh'}
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
              className="animate-pulse rounded-md border border-[#30343f] bg-[#191c24] p-5"
            >
              <div className="h-3 w-28 rounded bg-[#333542]" />
              <div className="mt-5 h-9 w-32 rounded bg-[#333542]" />
              <div className="mt-4 h-2 w-36 rounded bg-[#292d38]" />
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
          className="mb-4 rounded-md border border-[#633b43] bg-[#2b1d24] px-4 py-3 text-xs text-[#e5a4ac]"
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

          <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-b border-[#30343f] py-3 font-mono text-[10px] text-[#89909e]">
            <div className="flex items-center gap-2">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  error
                    ? 'bg-[#e18b91]'
                    : loading
                      ? 'animate-pulse bg-[#a69acb]'
                      : 'bg-[#79bba5]'
                }`}
              />

              <span>
                {error
                  ? 'Last successful response'
                  : loading
                    ? 'Updating intelligence'
                    : 'API connected'}
              </span>
            </div>

            <span>
              Updated{' '}
              {new Date(
                summary.generatedAtUtc,
              ).toLocaleString()}
            </span>
          </div>
        </>
      )}
    </section>
  )
}
