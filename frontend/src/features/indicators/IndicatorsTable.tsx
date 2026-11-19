
import { useState } from 'react'

import type {
  IndicatorListItem,
} from '../../types/indicators'

interface IndicatorsTableProps {
  indicators: IndicatorListItem[]
  selectedIndicatorId: number | null
  onInvestigate: (indicatorId: number) => void
}

function formatDate(value: string): string {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return 'Invalid date'
  }

  return date.toLocaleString()
}

function getTypeStyle(type: string): string {
  switch (type) {
    case 'domain':
      return 'border-[#32765C] bg-[#102B22] text-[#85EDBA]'
    case 'url':
      return 'border-[#326A78] bg-[#10252C] text-[#7BDDEC]'
    case 'ip:port':
      return 'border-[#74603B] bg-[#292316] text-[#F0C383]'
    case 'md5_hash':
    case 'sha1_hash':
    case 'sha256_hash':
      return 'border-[#395F62] bg-[#152428] text-[#A4CFD0]'
    default:
      return 'border-[#3A5B50] bg-[#17231F] text-[#B1D8C5]'
  }
}

export function IndicatorsTable({
  indicators,
  selectedIndicatorId,
  onInvestigate,
}: IndicatorsTableProps) {
  const [copiedId, setCopiedId] =
    useState<number | null>(null)

  const [copyError, setCopyError] =
    useState<string | null>(null)

  async function copyIndicator(
    indicator: IndicatorListItem,
  ): Promise<void> {
    try {
      await navigator.clipboard.writeText(
        indicator.normalizedValue,
      )

      setCopiedId(indicator.id)
      setCopyError(null)
    } catch {
      setCopiedId(null)
      setCopyError(
        'Unable to copy this indicator. Check clipboard permissions.',
      )
    }
  }

  function renderActions(
    indicator: IndicatorListItem,
    mobile: boolean,
  ) {
    const selected =
      selectedIndicatorId === indicator.id

    return (
      <div
        className={
          mobile
            ? 'grid grid-cols-2 gap-2'
            : 'flex items-center justify-end gap-2'
        }
      >
        <button
          type="button"
          onClick={() => {
            void copyIndicator(indicator)
          }}
          aria-label={`Copy indicator ${indicator.id} value`}
          className="min-h-10 rounded border border-[#356E57] bg-[#143024] px-3 py-2 font-mono text-[10px] font-medium tracking-wide text-[#9AE9C5] transition-colors hover:border-[#70E3B4] hover:bg-[#1B4433] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#51E9B5]"
        >
          {copiedId === indicator.id
            ? '✓ COPIED'
            : 'COPY'}
        </button>

        <button
          type="button"
          onClick={() =>
            onInvestigate(indicator.id)
          }
          aria-expanded={selected}
          aria-haspopup="dialog"
          aria-controls={
            selected
              ? 'indicator-investigation'
              : undefined
          }
          className={`min-h-10 rounded border px-3 py-2 font-mono text-[10px] font-medium tracking-wide transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#51E9B5] ${
            selected
              ? 'border-[#70E3B4] bg-[#24533D] text-[#D4FFE8]'
              : 'border-[#367789] bg-[#102B32] text-[#8DE4F2] hover:border-[#6CD8EC] hover:bg-[#19404B]'
          }`}
        >
          {selected ? 'SELECTED' : 'INVESTIGATE'}
        </button>
      </div>
    )
  }

  return (
    <div className="min-w-0 space-y-3">
      <div className="overflow-hidden rounded border border-[#2C5246] bg-[#101A1D]">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#294A40] bg-[#0D1A1B] px-4 py-3">
          <div className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="h-2 w-2 rounded-sm bg-[#51E9B5]"
            />

            <h2 className="font-mono text-[10px] font-medium tracking-[0.12em] text-[#A4E7C8]">
              INDICATOR INVENTORY
            </h2>
          </div>

          <span className="font-mono text-[9px] tracking-wider text-[#729F8F]">
            CANONICAL IOC RECORDS
          </span>
        </div>

        {/* Mobile and tablet IOC cards */}
        <div className="space-y-3 p-3 lg:hidden">
          {indicators.map((indicator) => {
            const selected =
              selectedIndicatorId === indicator.id

            return (
              <article
                key={indicator.id}
                className={`min-w-0 overflow-hidden rounded border transition-colors ${
                  selected
                    ? 'border-[#4FBA8B] bg-[#143126]'
                    : 'border-[#294A40] bg-[#0D191A]'
                }`}
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#29483E] px-3 py-3">
                  <span className="font-mono text-[10px] text-[#83B6A4]">
                    IOC_ID #{indicator.id}
                  </span>

                  <span
                    className={`inline-flex rounded border px-2.5 py-1 font-mono text-[10px] ${getTypeStyle(indicator.indicatorType)}`}
                  >
                    {indicator.indicatorType}
                  </span>
                </div>

                <div className="min-w-0 space-y-4 p-3">
                  <div className="min-w-0">
                    <p className="font-mono text-[10px] tracking-wider text-[#779F8E]">
                      INDICATOR VALUE
                    </p>

                    <p className="mt-2 break-all font-mono text-[12px] leading-6 text-[#D5F3E5]">
                      {indicator.normalizedValue}
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 border-t border-[#29483E] pt-3">
                    <div className="min-w-0">
                      <p className="font-mono text-[10px] tracking-wider text-[#779F8E]">
                        OBSERVATIONS
                      </p>

                      <p className="mt-2 font-mono text-lg font-semibold tabular-nums text-[#67E6B7]">
                        {indicator.observationCount.toLocaleString()}
                      </p>
                    </div>

                    <div className="min-w-0">
                      <p className="font-mono text-[10px] tracking-wider text-[#779F8E]">
                        FIRST STORED
                      </p>

                      <p className="mt-2 font-mono text-[11px] leading-5 text-[#A7CEBD]">
                        {formatDate(indicator.createdAtUtc)}
                      </p>
                    </div>
                  </div>

                  {renderActions(indicator, true)}
                </div>
              </article>
            )
          })}

          {indicators.length === 0 && (
            <div className="px-4 py-12 text-center font-mono text-xs text-[#83A899]">
              NO MATCHING INDICATORS FOUND
            </div>
          )}
        </div>

        {/* Desktop IOC table */}
        <div className="hidden overflow-x-auto lg:block">
          <table className="w-full min-w-[900px] border-collapse text-left">
            <thead className="bg-[#122125]">
              <tr className="border-b border-[#29483F]">
                <th
                  scope="col"
                  className="px-4 py-3 font-mono text-[10px] font-medium tracking-wider text-[#83B6A4]"
                >
                  INDICATOR / VALUE
                </th>

                <th
                  scope="col"
                  className="px-4 py-3 font-mono text-[10px] font-medium tracking-wider text-[#83B6A4]"
                >
                  TYPE
                </th>

                <th
                  scope="col"
                  className="px-4 py-3 text-right font-mono text-[10px] font-medium tracking-wider text-[#83B6A4]"
                >
                  OBSERVATIONS
                </th>

                <th
                  scope="col"
                  className="px-4 py-3 font-mono text-[10px] font-medium tracking-wider text-[#83B6A4]"
                >
                  FIRST STORED
                </th>

                <th
                  scope="col"
                  className="px-4 py-3 text-right font-mono text-[10px] font-medium tracking-wider text-[#83B6A4]"
                >
                  ACTIONS
                </th>
              </tr>
            </thead>

            <tbody>
              {indicators.map((indicator) => {
                const selected =
                  selectedIndicatorId === indicator.id

                return (
                  <tr
                    key={indicator.id}
                    className={`border-b border-[#233B37] transition-colors last:border-b-0 ${
                      selected
                        ? 'bg-[#15352A]'
                        : 'hover:bg-[#152923]'
                    }`}
                  >
                    <td className="max-w-[390px] px-4 py-3.5">
                      <div className="space-y-1.5">
                        <div
                          title={indicator.normalizedValue}
                          className="max-w-[350px] truncate font-mono text-[12px] text-[#D5F3E5]"
                        >
                          {indicator.normalizedValue}
                        </div>

                        <span className="font-mono text-[10px] text-[#678F81]">
                          IOC_ID #{indicator.id}
                        </span>
                      </div>
                    </td>

                    <td className="px-4 py-3.5">
                      <span
                        className={`inline-flex whitespace-nowrap rounded border px-2.5 py-1 font-mono text-[10px] ${getTypeStyle(indicator.indicatorType)}`}
                      >
                        {indicator.indicatorType}
                      </span>
                    </td>

                    <td className="px-4 py-3.5 text-right">
                      <span className="font-mono text-[13px] font-medium tabular-nums text-[#67E6B7]">
                        {indicator.observationCount.toLocaleString()}
                      </span>
                    </td>

                    <td className="whitespace-nowrap px-4 py-3.5 font-mono text-[11px] text-[#8FB4A6]">
                      {formatDate(indicator.createdAtUtc)}
                    </td>

                    <td className="px-4 py-3.5">
                      {renderActions(indicator, false)}
                    </td>
                  </tr>
                )
              })}

              {indicators.length === 0 && (
                <tr>
                  <td
                    colSpan={5}
                    className="px-4 py-14 text-center font-mono text-xs text-[#83A899]"
                  >
                    NO MATCHING INDICATORS FOUND
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#294A40] bg-[#0D1A1B] px-4 py-3">
          <span className="font-mono text-[10px] text-[#79A794]">
            SOURCE: THREATFORGE INTELLIGENCE API
          </span>

          <span className="font-mono text-[10px] text-[#719B8B]">
            IOC VALUES ARE NOT OPENED AUTOMATICALLY
          </span>
        </div>
      </div>

      {copyError && (
        <div
          role="alert"
          className="rounded border border-[#794447] bg-[#2A191C] px-4 py-3 text-xs text-[#FFAAAA]"
        >
          {copyError}
        </div>
      )}
    </div>
  )
}
