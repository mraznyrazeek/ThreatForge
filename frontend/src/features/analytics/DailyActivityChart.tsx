
import { useEffect, useMemo, useRef, useState } from 'react'

import * as echarts from 'echarts/core'
import { LineChart } from 'echarts/charts'
import {
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components'
import { SVGRenderer } from 'echarts/renderers'

import type {
  DailyThreatActivityResponse,
  DailyThreatActivityItem,
} from '../../types/analytics'

echarts.use([
  LineChart,
  DataZoomComponent,
  GridComponent,
  LegendComponent,
  TooltipComponent,
  SVGRenderer,
])

interface DailyActivityChartProps {
  data: DailyThreatActivityResponse
}

type ActivityMetric =
  | 'observationCount'
  | 'distinctIndicatorCount'

const COLORS = [
  '#B6A0EF',
  '#65B8B1',
  '#D5A36D',
  '#7F9FD6',
  '#D28DAD',
  '#96B9CA',
]

const numberFormatter = new Intl.NumberFormat('en-US')

const METRIC_LABELS: Record<ActivityMetric, string> = {
  observationCount: 'Observations',
  distinctIndicatorCount: 'Distinct indicators',
}

function formatDate(date: string): string {
  const parts = date.split('-')

  if (parts.length !== 3) {
    return date
  }

  return `${parts[1]}/${parts[2]}`
}

export function DailyActivityChart({
  data,
}: DailyActivityChartProps) {
  const chartRef = useRef<HTMLDivElement | null>(null)

  const [metric, setMetric] =
    useState<ActivityMetric>('observationCount')

  const records = useMemo(
    () =>
      [...data.dailyActivity].sort(
        (a, b) =>
          a.dateUtc.localeCompare(b.dateUtc) ||
          a.sourceName.localeCompare(b.sourceName),
      ),
    [data.dailyActivity],
  )

  const dates = useMemo(
    () =>
      [...new Set(records.map((item) => item.dateUtc))]
        .sort(),
    [records],
  )

  const sources = useMemo(
    () =>
      [...new Set(records.map((item) => item.sourceName))]
        .sort(),
    [records],
  )

  const hasData =
    records.length > 0 &&
    dates.length > 0 &&
    sources.length > 0

  const dateRange = useMemo(() => {
    if (dates.length === 0) {
      return 'No activity dates'
    }

    if (dates.length === 1) {
      return dates[0]
    }

    return `${dates[0]} — ${dates[dates.length - 1]}`
  }, [dates])

  const sourceSeries = useMemo(() => {
    return sources.map((sourceName, index) => {
      const sourceRecords = records.filter(
        (item) => item.sourceName === sourceName,
      )

      const recordsByDate = new Map<
        string,
        DailyThreatActivityItem
      >()

      sourceRecords.forEach((item) => {
        recordsByDate.set(item.dateUtc, item)
      })

      return {
        name: sourceName,
        color: COLORS[index % COLORS.length],
        values: dates.map((date) => {
          const record = recordsByDate.get(date)

          return record ? record[metric] : null
        }),
      }
    })
  }, [sources, records, dates, metric])

  useEffect(() => {
    const element = chartRef.current

    if (!element || !hasData) {
      return
    }

    const chart = echarts.init(element, undefined, {
      renderer: 'svg',
    })

    chart.setOption({
      backgroundColor: 'transparent',

      color: sourceSeries.map((item) => item.color),

      animationDuration: 600,

      legend: {
        type: 'scroll',
        top: 6,
        left: 8,
        right: 8,

        icon: 'roundRect',
        itemWidth: 13,
        itemHeight: 7,
        itemGap: 18,

        textStyle: {
          color: '#C2C3D0',
          fontSize: 11,
        },

        pageTextStyle: {
          color: '#A6A2B7',
        },
      },

      tooltip: {
        trigger: 'axis',
        confine: true,

        axisPointer: {
          type: 'cross',
          label: {
            backgroundColor: '#353043',
          },
        },

        backgroundColor: '#222530',
        borderColor: '#494457',
        borderWidth: 1,

        textStyle: {
          color: '#ECE8F5',
          fontSize: 12,
        },

        valueFormatter: (value: unknown) => {
          if (typeof value === 'number') {
            return numberFormatter.format(value)
          }

          return 'No record'
        },
      },

      grid: {
        top: 60,
        left: 64,
        right: 28,
        bottom: 105,
        containLabel: false,
      },

      xAxis: {
        type: 'category',
        boundaryGap: false,
        data: dates,

        axisLine: {
          lineStyle: {
            color: '#424653',
          },
        },

        axisTick: {
          show: false,
        },

        axisLabel: {
          color: '#9599A8',
          fontSize: 10,
          hideOverlap: true,
          formatter: (value: string) =>
            formatDate(value),
        },

        splitLine: {
          show: false,
        },
      },

      yAxis: {
        type: 'value',
        min: 0,

        name: METRIC_LABELS[metric],

        nameTextStyle: {
          color: '#9296A5',
          fontSize: 10,
          padding: [0, 0, 5, 0],
        },

        axisLine: {
          show: false,
        },

        axisTick: {
          show: false,
        },

        axisLabel: {
          color: '#9296A5',
          fontSize: 10,
          formatter: (value: number) =>
            numberFormatter.format(value),
        },

        splitLine: {
          lineStyle: {
            color: '#303440',
            type: 'dashed',
          },
        },
      },

      dataZoom: [
        {
          type: 'inside',
          xAxisIndex: 0,
          filterMode: 'none',
          start: dates.length > 30 ? 65 : 0,
          end: 100,
        },
        {
          type: 'slider',
          xAxisIndex: 0,
          filterMode: 'none',
          height: 20,
          bottom: 32,

          start: dates.length > 30 ? 65 : 0,
          end: 100,

          borderColor: '#3C4050',
          backgroundColor: '#20232D',
          fillerColor: 'rgba(169, 153, 223, 0.17)',

          handleStyle: {
            color: '#A999DF',
            borderColor: '#B6A0EF',
          },

          moveHandleStyle: {
            color: '#A999DF',
          },

          textStyle: {
            color: '#9296A5',
            fontSize: 10,
          },

          dataBackground: {
            lineStyle: {
              color: '#71658F',
            },
            areaStyle: {
              color: '#302B41',
            },
          },
        },
      ],

      series: sourceSeries.map((source) => ({
        name: source.name,
        type: 'line',

        data: source.values,

        smooth: false,
        connectNulls: false,

        showSymbol: false,
        symbol: 'circle',
        symbolSize: 7,

        lineStyle: {
          width: 2.5,
          color: source.color,
        },

        itemStyle: {
          color: source.color,
        },

        emphasis: {
          focus: 'series',
          scale: true,
        },
      })),
    })

    const observer = new ResizeObserver(() => {
      chart.resize()
    })

    observer.observe(element)

    return () => {
      observer.disconnect()
      chart.dispose()
    }
  }, [hasData, dates, sourceSeries, metric])

  return (
    <section
      aria-labelledby="activity-heading"
      className="overflow-hidden rounded-lg border border-[#30343F] bg-[#191C24]"
    >
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#30343F] px-5 py-4">
        <div>
          <h2
            id="activity-heading"
            className="text-sm font-semibold text-[#EEEAF5]"
          >
            Threat activity timeline
          </h2>

          <p className="mt-1 text-xs text-[#9296A4]">
            Daily intelligence activity by source
          </p>
        </div>

        <div className="flex rounded-md border border-[#3C4050] bg-[#14161D] p-1">
          {(
            [
              'observationCount',
              'distinctIndicatorCount',
            ] as const
          ).map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={metric === value}
              onClick={() => setMetric(value)}
              className={`rounded px-3 py-1.5 text-[11px] font-medium transition-colors ${
                metric === value
                  ? 'bg-[#393048] text-[#E0D4FA]'
                  : 'text-[#9599A8] hover:text-[#DFDAEA]'
              }`}
            >
              {value === 'observationCount'
                ? 'Observations'
                : 'Distinct IOCs'}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-3 border-b border-[#30343F] px-5 py-4 sm:grid-cols-3">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-[#89909E]">
            Total observations
          </p>

          <p className="mt-1 font-mono text-lg font-semibold tabular-nums text-[#EDE9F5]">
            {numberFormatter.format(data.totalObservations)}
          </p>
        </div>

        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-[#89909E]">
            Intelligence sources
          </p>

          <p className="mt-1 font-mono text-lg font-semibold tabular-nums text-[#EDE9F5]">
            {sources.length}
          </p>
        </div>

        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-[#89909E]">
            Activity dates
          </p>

          <p className="mt-1 font-mono text-lg font-semibold tabular-nums text-[#EDE9F5]">
            {numberFormatter.format(dates.length)}
          </p>
        </div>
      </div>

      {!hasData ? (
        <div className="px-5 py-16 text-center text-sm text-[#9296A4]">
          No daily threat activity data available.
        </div>
      ) : (
        <div className="px-3 py-4 sm:px-5">
          <div className="overflow-x-auto">
            <div className="min-w-[530px]">
              <div
                ref={chartRef}
                className="h-[390px] w-full"
                role="img"
                aria-label={`Interactive daily activity timeline showing ${METRIC_LABELS[metric].toLowerCase()} across ${sources.length} intelligence sources.`}
              />
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#30343F] px-5 py-3">
        <div className="space-y-1">
          <p className="font-mono text-[10px] text-[#A5A0B5]">
            {dateRange}
          </p>

          <p className="font-mono text-[10px] text-[#777E8D]">
            Source dates: {data.timezone}. Dates without a
            source record are not treated as zero activity.
          </p>
        </div>

        <time
          dateTime={data.generatedAtUtc}
          className="font-mono text-[10px] text-[#858A98]"
        >
          Generated:{' '}
          {new Date(data.generatedAtUtc).toLocaleString()}
        </time>
      </div>
    </section>
  )
}
