
import { useCallback, useEffect, useState } from 'react'
import { useAuth } from '../../auth/useAuth'
import { getThreatIndicators } from '../../services/indicatorsApi'
import type { PagedIndicatorsResponse } from '../../types/indicators'
import { IndicatorsTable } from './IndicatorsTable'

const DEFAULT_PAGE_SIZE = 20

export function IndicatorsPage() {
  const { getAccessToken } = useAuth()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)

  const [typeInput, setTypeInput] = useState('')
  const [indicatorType, setIndicatorType] = useState('')

  const [data, setData] =
    useState<PagedIndicatorsResponse | null>(null)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getThreatIndicators(
      getAccessToken,
      {
        page,
        pageSize,
        indicatorType: indicatorType || undefined,
      },
      controller.signal,
    )
      .then((response) => {
        if (!active) return

        setData(response)
        setError(null)
        setLoading(false)
      })
      .catch((requestError: unknown) => {
        if (!active || controller.signal.aborted) return

        setError(
          requestError instanceof Error
            ? requestError.message
            : 'Unable to retrieve threat indicators.',
        )

        setLoading(false)
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [
    getAccessToken,
    page,
    pageSize,
    indicatorType,
    refreshKey,
  ])

  const applyFilter = useCallback(() => {
    const normalizedType = typeInput.trim()

    if (normalizedType.length > 64) {
      setError('Indicator type must not exceed 64 characters.')
      return
    }

    setLoading(true)
    setError(null)
    setData(null)
    setPage(1)
    setIndicatorType(normalizedType)
  }, [typeInput])

  const clearFilter = useCallback(() => {
    setTypeInput('')
    setIndicatorType('')
    setPage(1)
    setLoading(true)
    setError(null)
    setData(null)
  }, [])

  const changePageSize = useCallback((size: number) => {
    setPageSize(size)
    setPage(1)
    setLoading(true)
    setError(null)
    setData(null)
  }, [])

  const changePage = useCallback((nextPage: number) => {
    setPage(nextPage)
    setLoading(true)
    setError(null)
    setData(null)
  }, [])

  const refresh = useCallback(() => {
    setLoading(true)
    setError(null)
    setData(null)
    setRefreshKey((previous) => previous + 1)
  }, [])

  const rangeStart =
    data && data.totalItems > 0
      ? (data.page - 1) * data.pageSize + 1
      : 0

  const rangeEnd = data
    ? Math.min(
        data.page * data.pageSize,
        data.totalItems,
      )
    : 0

  return (
    <section
      aria-labelledby="indicators-heading"
      className="space-y-5"
    >
      {/* Page heading */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <p className="font-mono text-[10px] text-[#8E92A0]">
            Intelligence / Indicators
          </p>

          <h1
            id="indicators-heading"
            className="mt-2 text-[25px] font-semibold tracking-[-0.04em] text-[#F1F0F5]"
          >
            Threat Indicators
          </h1>

          <p className="mt-1 text-xs text-[#9296A4]">
            Browse indicators stored in the intelligence database.
          </p>
        </div>

        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="rounded-md border border-[#454251] bg-[#211F2B] px-4 py-2 text-xs font-medium text-[#C5B9E4] transition-colors hover:border-[#8E82BF] disabled:opacity-50"
        >
          {loading ? 'Loading...' : '↻ Refresh'}
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-end gap-3 rounded-md border border-[#30343F] bg-[#191C24] p-4">
        <form
          className="flex flex-1 flex-wrap items-end gap-3"
          onSubmit={(event) => {
            event.preventDefault()
            applyFilter()
          }}
        >
          <label className="flex min-w-[190px] flex-1 flex-col gap-2">
            <span className="font-mono text-[10px] uppercase tracking-wider text-[#989DAA]">
              Indicator type
            </span>

            <input
              type="text"
              value={typeInput}
              maxLength={64}
              onChange={(event) =>
                setTypeInput(event.target.value)
              }
              placeholder="Enter indicator type"
              className="h-9 w-full rounded-md border border-[#414552] bg-[#12151C] px-3 text-xs text-[#EEEAF5] placeholder:text-[#686D7B] focus:border-[#A69ACB] focus:outline-none"
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="h-9 rounded-md bg-[#B4A3DB] px-4 text-xs font-semibold text-[#1A1622] transition-colors hover:bg-[#D0C2EC] disabled:opacity-50"
          >
            Apply filter
          </button>

          <button
            type="button"
            onClick={clearFilter}
            disabled={loading}
            className="h-9 rounded-md border border-[#454955] px-4 text-xs text-[#C7C6D0] transition-colors hover:bg-[#292D38] disabled:opacity-50"
          >
            Clear
          </button>
        </form>

        <label className="flex flex-col gap-2">
          <span className="font-mono text-[10px] uppercase tracking-wider text-[#989DAA]">
            Rows per page
          </span>

          <select
            value={pageSize}
            disabled={loading}
            onChange={(event) =>
              changePageSize(Number(event.target.value))
            }
            className="h-9 rounded-md border border-[#414552] bg-[#12151C] px-3 text-xs text-[#EEEAF5] focus:border-[#A69ACB] focus:outline-none"
          >
            <option value={10}>10</option>
            <option value={20}>20</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
          </select>
        </label>
      </div>

      {/* Active filter */}
      {indicatorType && (
        <div className="flex items-center gap-2 text-xs text-[#A9A2BD]">
          <span>Filtering by type:</span>

          <span className="rounded border border-[#524966] bg-[#2B263A] px-2 py-1 font-mono text-[10px] text-[#D1C5EF]">
            {indicatorType}
          </span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div
          role="status"
          className="rounded-md border border-[#30343F] bg-[#191C24] p-8"
        >
          <div className="flex items-center gap-3">
            <span className="h-4 w-4 animate-spin rounded-full border-2 border-[#474155] border-t-[#B4A3DB]" />

            <span className="text-xs text-[#A7A5B5]">
              Loading threat indicators...
            </span>
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div
          role="alert"
          className="rounded-md border border-[#69434A] bg-[#2B1E23] px-4 py-3 text-xs text-[#E5A4AC]"
        >
          {error}
        </div>
      )}

      {/* Results */}
      {!loading && !error && data && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-[#9095A3]">
            <span>
              Showing{' '}
              <strong className="font-medium text-[#E0DEE7]">
                {rangeStart.toLocaleString()}–
                {rangeEnd.toLocaleString()}
              </strong>{' '}
              of{' '}
              <strong className="font-medium text-[#E0DEE7]">
                {data.totalItems.toLocaleString()}
              </strong>{' '}
              indicators
            </span>

            <span className="font-mono text-[10px]">
              Page {data.page.toLocaleString()} of{' '}
              {data.totalPages.toLocaleString()}
            </span>
          </div>

          <IndicatorsTable indicators={data.items} />

          {/* Pagination */}
          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-[#30343F] pt-4">
            <span className="font-mono text-[10px] text-[#89909E]">
              {data.totalItems.toLocaleString()} matching records
            </span>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={!data.hasPreviousPage}
                onClick={() => changePage(data.page - 1)}
                className="rounded-md border border-[#414552] px-3 py-2 text-xs text-[#C7C6D0] transition-colors hover:border-[#8E82BF] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>

              <span className="min-w-16 text-center font-mono text-xs text-[#D6D3DE]">
                {data.page} / {data.totalPages}
              </span>

              <button
                type="button"
                disabled={!data.hasNextPage}
                onClick={() => changePage(data.page + 1)}
                className="rounded-md border border-[#414552] px-3 py-2 text-xs text-[#C7C6D0] transition-colors hover:border-[#8E82BF] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </section>
  )
}
