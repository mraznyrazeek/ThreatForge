
import type {
  IndicatorListItem,
} from '../../types/indicators'

interface IndicatorsTableProps {
  indicators: IndicatorListItem[]
}

function formatDate(value: string): string {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return 'Invalid date'
  }

  return date.toLocaleString()
}

export function IndicatorsTable({
  indicators,
}: IndicatorsTableProps) {
  return (
    <div className="overflow-x-auto rounded-md border border-[#30343F] bg-[#191C24]">
      <table className="w-full min-w-[580px] border-collapse text-left">
        <thead className="border-b border-[#30343F] bg-[#20232C]">
          <tr>
            <th
              scope="col"
              className="px-4 py-3 font-mono text-[10px] font-medium uppercase tracking-wider text-[#949AAA]"
            >
              Indicator ID
            </th>

            <th
              scope="col"
              className="px-4 py-3 font-mono text-[10px] font-medium uppercase tracking-wider text-[#949AAA]"
            >
              Indicator Type
            </th>

            <th
              scope="col"
              className="px-4 py-3 font-mono text-[10px] font-medium uppercase tracking-wider text-[#949AAA]"
            >
              Created
            </th>
          </tr>
        </thead>

        <tbody>
          {indicators.map((indicator) => (
            <tr
              key={indicator.id}
              className="border-b border-[#2B303B] transition-colors last:border-0 hover:bg-[#222530]"
            >
              <td className="px-4 py-3 font-mono text-xs tabular-nums text-[#DADCE6]">
                {indicator.id}
              </td>

              <td className="px-4 py-3">
                <span className="inline-flex rounded border border-[#4B435F] bg-[#292536] px-2 py-1 font-mono text-[10px] text-[#C8B9EA]">
                  {indicator.indicatorType}
                </span>
              </td>

              <td className="px-4 py-3 font-mono text-[11px] text-[#999EAC]">
                {formatDate(indicator.createdAtUtc)}
              </td>
            </tr>
          ))}

          {indicators.length === 0 && (
            <tr>
              <td
                colSpan={3}
                className="px-4 py-12 text-center text-sm text-[#9297A5]"
              >
                No indicators found.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
