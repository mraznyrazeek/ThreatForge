
import { useCallback, useEffect, useState } from 'react'

import { useAuth } from '../../auth/useAuth'

import {
  getThreatIndicators,
  getThreatIndicatorDetail,
} from '../../services/indicatorsApi'

import type {
  PagedIndicatorsResponse,
} from '../../types/indicators'

import type {
  IndicatorDetailResponse,
} from '../../types/indicatorDetail'

import { IndicatorsTable } from './IndicatorsTable'
import { IndicatorInvestigationModal } from './IndicatorInvestigationModal'

const DEFAULT_PAGE_SIZE = 20
const MAX_TYPE_LENGTH = 64
const MAX_SEARCH_LENGTH = 256

type DetailState = {
  indicatorId: number
  data: IndicatorDetailResponse | null
  loading: boolean
  error: string | null
}

export function IndicatorsPage() {
  const { getAccessToken } = useAuth()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE)

  const [typeInput, setTypeInput] = useState('')
  const [searchInput, setSearchInput] = useState('')

  const [indicatorType, setIndicatorType] = useState('')
  const [search, setSearch] = useState('')

  const [data, setData] =
    useState<PagedIndicatorsResponse | null>(null)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [validationError, setValidationError] =
    useState<string | null>(null)

  const [refreshKey, setRefreshKey] = useState(0)

  const [selectedIndicatorId, setSelectedIndicatorId] =
    useState<number | null>(null)

  const [detail, setDetail] =
    useState<DetailState | null>(null)

  // Fetch server-side paginated and filtered results.
  useEffect(() => {
    const controller = new AbortController()
    let active = true

    getThreatIndicators(
      getAccessToken,
      {
        page,
        pageSize,
        indicatorType: indicatorType || undefined,
        search: search || undefined,
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

        setData(null)
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
    search,
    refreshKey,
  ])

  // Fetch source evidence for the active investigation.
  useEffect(() => {
    if (selectedIndicatorId === null) {
      return
    }

    const controller = new AbortController()
    let active = true
    const indicatorId = selectedIndicatorId

    getThreatIndicatorDetail(
      getAccessToken,
      indicatorId,
      controller.signal,
    )
      .then((response) => {
        if (!active) return

        setDetail({
          indicatorId,
          data: response,
          loading: false,
          error: null,
        })
      })
      .catch((requestError: unknown) => {
        if (!active || controller.signal.aborted) return

        setDetail({
          indicatorId,
          data: null,
          loading: false,
          error:
            requestError instanceof Error
              ? requestError.message
              : 'Unable to retrieve indicator intelligence.',
        })
      })

    return () => {
      active = false
      controller.abort()
    }
  }, [getAccessToken, selectedIndicatorId])

  const closeInvestigation = useCallback(() => {
    setSelectedIndicatorId(null)
    setDetail(null)
  }, [])

  const investigate = useCallback(
    (indicatorId: number) => {
      if (selectedIndicatorId === indicatorId) {
        closeInvestigation()
        return
      }

      setDetail({
        indicatorId,
        data: null,
        loading: true,
        error: null,
      })

      setSelectedIndicatorId(indicatorId)
    },
    [selectedIndicatorId, closeInvestigation],
  )

  const applyFilter = useCallback(() => {
    const normalizedType = typeInput.trim()
    const normalizedSearch = searchInput.trim()

    if (typeInput.length > MAX_TYPE_LENGTH) {
      setValidationError(
        'Indicator type must not exceed 64 characters.',
      )
      return
    }

    if (searchInput.length > MAX_SEARCH_LENGTH) {
      setValidationError(
        'IOC search must not exceed 256 characters.',
      )
      return
    }

    closeInvestigation()
    setValidationError(null)
    setError(null)
    setLoading(true)
    setData(null)

    setPage(1)
    setIndicatorType(normalizedType)
    setSearch(normalizedSearch)

    // Re-run the request even when filters are unchanged.
    setRefreshKey((previous) => previous + 1)
  }, [typeInput, searchInput, closeInvestigation])

  const clearFilter = useCallback(() => {
    closeInvestigation()

    setTypeInput('')
    setSearchInput('')
    setIndicatorType('')
    setSearch('')
    setPage(1)

    setError(null)
    setValidationError(null)
    setLoading(true)
    setData(null)
    setRefreshKey((previous) => previous + 1)
  }, [closeInvestigation])

  const changePageSize = useCallback(
    (size: number) => {
      closeInvestigation()
      setPageSize(size)
      setPage(1)
      setLoading(true)
      setError(null)
      setData(null)
    },
    [closeInvestigation],
  )

  const changePage = useCallback(
    (nextPage: number) => {
      closeInvestigation()
      setPage(nextPage)
      setLoading(true)
      setError(null)
      setData(null)
    },
    [closeInvestigation],
  )

  const refresh = useCallback(() => {
    closeInvestigation()
    setLoading(true)
    setError(null)
    setData(null)
    setRefreshKey((previous) => previous + 1)
  }, [closeInvestigation])

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

  const activeDetail =
    selectedIndicatorId !== null &&
    detail?.indicatorId === selectedIndicatorId
      ? detail
      : null

  const hasActiveFilters = Boolean(
    indicatorType || search,
  )

  return (
    <section
      aria-labelledby="indicators-heading"
      className="min-w-0 space-y-5"
    >
      {/* Page heading */}
      <div className="flex flex-wrap items-end justify-between gap-4 border-b border-[#29473D] pb-5">
        <div>
          <p className="font-mono text-[10px] tracking-wide text-[#79BA9D]">
            THREATFORGE / INTELLIGENCE / INDICATORS
          </p>

          <div className="mt-3 flex items-center gap-3">
            <span
              aria-hidden="true"
              className="h-7 w-[3px] rounded bg-[#51E9B5] shadow-[0_0_12px_rgba(81,233,181,0.3)]"
            />

            <h1
              id="indicators-heading"
              className="text-[clamp(1.5rem,3vw,2rem)] font-semibold tracking-[-0.045em] text-[#E8FFF5]"
            >
              Threat Indicators
            </h1>
          </div>

          <p className="mt-2 text-xs text-[#8BAA9E]">
            Search canonical IOCs and investigate
            source-specific threat intelligence
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

      {/* Search and filter console */}
      <div className="overflow-hidden rounded border border-[#2C5246] bg-[#101A1D]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#294A40] bg-[#0D1A1B] px-4 py-3">
          <span className="font-mono text-[10px] font-medium tracking-[0.12em] text-[#A4E7C8]">
            // IOC SEARCH CONSOLE
          </span>

          <span className="font-mono text-[9px] text-[#729F8F]">
            POSTGRESQL / SERVER-SIDE QUERY
          </span>
        </div>

        <form
          className="space-y-4 p-4"
          onSubmit={(event) => {
            event.preventDefault()
            applyFilter()
          }}
        >
          <label className="flex min-w-0 flex-col gap-2">
            <span className="font-mono text-[10px] tracking-wider text-[#83B6A4]">
              SEARCH IOC VALUE
            </span>

            <input
              type="search"
              value={searchInput}
              maxLength={MAX_SEARCH_LENGTH}
              onChange={(event) => {
                setSearchInput(event.target.value)
                setValidationError(null)
              }}
              placeholder="Search URL, domain, IP address or hash..."
              autoComplete="off"
              className="h-11 w-full min-w-0 rounded border border-[#315446] bg-[#090F12] px-3 font-mono text-xs text-[#E1F7EA] placeholder:text-[#668B7D] focus:border-[#51E9B5] focus:outline-none"
            />

            <span className="font-mono text-[10px] text-[#789D8E]">
              Literal, case-insensitive substring search.
              Press Enter to apply.
            </span>
          </label>

          <div className="flex flex-wrap items-end gap-3">
            <label className="flex min-w-[180px] flex-1 flex-col gap-2">
              <span className="font-mono text-[10px] tracking-wider text-[#83B6A4]">
                INDICATOR TYPE
              </span>

              <input
                type="text"
                value={typeInput}
                maxLength={MAX_TYPE_LENGTH}
                onChange={(event) => {
                  setTypeInput(event.target.value)
                  setValidationError(null)
                }}
                placeholder="All types / domain / url / sha256_hash"
                className="h-10 w-full rounded border border-[#315446] bg-[#090F12] px-3 font-mono text-[11px] text-[#E1F7EA] placeholder:text-[#668B7D] focus:border-[#51E9B5] focus:outline-none"
              />
            </label>

            <label className="flex flex-col gap-2">
              <span className="font-mono text-[10px] tracking-wider text-[#83B6A4]">
                ROWS PER PAGE
              </span>

              <select
                value={pageSize}
                disabled={loading}
                onChange={(event) =>
                  changePageSize(
                    Number(event.target.value),
                  )
                }
                className="h-10 rounded border border-[#315446] bg-[#090F12] px-3 font-mono text-[11px] text-[#E1F7EA] focus:border-[#51E9B5] focus:outline-none"
              >
                <option value={10}>10</option>
                <option value={20}>20</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </label>

            <button
              type="submit"
              disabled={loading}
              className="h-10 rounded border border-[#4BA67F] bg-[#1C4B39] px-5 font-mono text-[10px] font-semibold tracking-wide text-[#BCF7DB] transition-colors hover:bg-[#27674D] disabled:opacity-50"
            >
              SEARCH
            </button>

            <button
              type="button"
              onClick={clearFilter}
              disabled={loading}
              className="h-10 rounded border border-[#36564A] bg-[#14231F] px-4 font-mono text-[10px] text-[#A8D1BD] transition-colors hover:bg-[#1D352A] disabled:opacity-50"
            >
              CLEAR
            </button>
          </div>
        </form>
      </div>

      {/* Applied filters */}
      {hasActiveFilters && (
        <div className="flex flex-wrap items-center gap-2 font-mono text-[10px] text-[#8FB9A6]">
          <span>ACTIVE FILTERS:</span>

          {search && (
            <span className="max-w-full break-all rounded border border-[#367789] bg-[#102B32] px-2.5 py-1 text-[#8DE4F2]">
              SEARCH: {search}
            </span>
          )}

          {indicatorType && (
            <span className="rounded border border-[#34785E] bg-[#123225] px-2.5 py-1 text-[#9CEFC6]">
              TYPE: {indicatorType}
            </span>
          )}
        </div>
      )}

      {validationError && (
        <div
          role="alert"
          className="rounded border border-[#795B37] bg-[#2A2117] px-4 py-3 text-xs text-[#E9C18A]"
        >
          {validationError}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div
          role="status"
          className="flex items-center gap-3 rounded border border-[#2C5246] bg-[#101A1D] p-6"
        >
          <span className="h-4 w-4 animate-spin rounded-full border-2 border-[#31594C] border-t-[#51E9B5]" />

          <span className="font-mono text-xs text-[#A1D5BE]">
            SEARCHING THREAT INTELLIGENCE...
          </span>
        </div>
      )}

      {/* API errors */}
      {error && !loading && (
        <div
          role="alert"
          className="rounded border border-[#794447] bg-[#2A191C] px-4 py-3 text-xs text-[#FFAAAA]"
        >
          {error}
        </div>
      )}

      {/* Search results */}
      {!loading && !error && data && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 font-mono text-[10px] text-[#8FB4A4]">
            <span>
              SHOWING{' '}
              <strong className="font-medium text-[#B8F3D8]">
                {rangeStart.toLocaleString()}–
                {rangeEnd.toLocaleString()}
              </strong>{' '}
              OF{' '}
              <strong className="font-medium text-[#B8F3D8]">
                {data.totalItems.toLocaleString()}
              </strong>{' '}
              MATCHING INDICATORS
            </span>

            <span>
              PAGE {data.page.toLocaleString()} /{' '}
              {data.totalPages.toLocaleString()}
            </span>
          </div>

          <IndicatorsTable
            indicators={data.items}
            selectedIndicatorId={selectedIndicatorId}
            onInvestigate={investigate}
          />

          <div className="flex flex-wrap items-center justify-between gap-4 border-t border-[#29473D] pt-4">
            <span className="font-mono text-[10px] text-[#779F8D]">
              {data.totalItems.toLocaleString()} MATCHING RECORDS
            </span>

            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={loading || !data.hasPreviousPage}
                onClick={() => changePage(data.page - 1)}
                className="rounded border border-[#365E4E] bg-[#12251E] px-3 py-2 font-mono text-[10px] text-[#ADDCC5] transition-colors hover:border-[#63D9A7] disabled:cursor-not-allowed disabled:opacity-40"
              >
                PREVIOUS
              </button>

              <span className="min-w-20 text-center font-mono text-[11px] text-[#C5EBD9]">
                {data.page} / {data.totalPages}
              </span>

              <button
                type="button"
                disabled={loading || !data.hasNextPage}
                onClick={() => changePage(data.page + 1)}
                className="rounded border border-[#365E4E] bg-[#12251E] px-3 py-2 font-mono text-[10px] text-[#ADDCC5] transition-colors hover:border-[#63D9A7] disabled:cursor-not-allowed disabled:opacity-40"
              >
                NEXT
              </button>
            </div>
          </div>
        </>
      )}

      {/* Modal is rendered independently of the table. */}
      {selectedIndicatorId !== null && (
        <IndicatorInvestigationModal
          indicatorId={selectedIndicatorId}
          data={activeDetail?.data ?? null}
          loading={activeDetail?.loading ?? true}
          error={activeDetail?.error ?? null}
          onClose={closeInvestigation}
        />
      )}
    </section>
  )
}
