
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
  '#51E9B5',
  '#61D8EB',
  '#F3B66A',
  '#91A9FF',
  '#EC93AE',
  '#B0D5CE',
]

const numberFormatter = new Intl.NumberFormat('en-US')

const METRIC_LABELS: Record<ActivityMetric, string> = {
  observationCount: 'Observations',
  distinctIndicatorCount: 'Distinct indicators',
}

function formatDate(date: string): string {
  const parts = date.split('-')

  if (parts.length !== 3) return date

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
    if (dates.length === 0) return 'No activity dates'
    if (dates.length === 1) return dates[0]

    return `${dates[0]} — ${dates[dates.length - 1]}`
  }, [dates])

  const sourceSeries = useMemo(() => {
    return sources.map((sourceName, index) => {
      const recordsByDate = new Map<
        string,
        DailyThreatActivityItem
      >()

      records
        .filter((item) => item.sourceName === sourceName)
        .forEach((item) => {
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

    if (!element || !hasData) return

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
        itemWidth: 14,
        itemHeight: 7,
        itemGap: 20,

        textStyle: {
          color: '#B0D8CA',
          fontSize: 11,
        },

        pageTextStyle: {
          color: '#85AD9D',
        },

        inactiveColor: '#52756A',
      },

      tooltip: {
        trigger: 'axis',
        confine: true,

        axisPointer: {
          type: 'cross',
          label: {
            backgroundColor: '#204439',
            color: '#DDF9EC',
          },

          crossStyle: {
            color: '#4C9B7D',
          },
        },

        backgroundColor: '#0B1919',
        borderColor: '#37725C',
        borderWidth: 1,
        padding: 12,

        textStyle: {
          color: '#E4F9EF',
          fontSize: 12,
        },

        valueFormatter: (value: unknown) =>
          typeof value === 'number'
            ? numberFormatter.format(value)
            : 'No record',
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
            color: '#335B4C',
          },
        },

        axisTick: {
          show: false,
        },

        axisLabel: {
          color: '#8BAF9F',
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
          color: '#87B5A3',
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
          color: '#8BAF9F',
          fontSize: 10,
          formatter: (value: number) =>
            numberFormatter.format(value),
        },

        splitLine: {
          lineStyle: {
            color: '#244039',
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

          borderColor: '#315548',
          backgroundColor: '#0C201B',
          fillerColor: 'rgba(81, 233, 181, 0.15)',

          handleStyle: {
            color: '#51E9B5',
            borderColor: '#85F4CA',
          },

          moveHandleStyle: {
            color: '#51E9B5',
          },

          textStyle: {
            color: '#83AB99',
            fontSize: 10,
          },

          dataBackground: {
            lineStyle: {
              color: '#438A70',
            },
            areaStyle: {
              color: '#153B2D',
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
          shadowColor: source.color,
          shadowBlur: 5,
          shadowOffsetY: 0,
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
      className="tf-glow-border overflow-hidden rounded border border-[#2C5749] bg-[#101A1D]"
    >
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#294A40] bg-[#0D1A1B] px-5 py-4">
        <div>
          <p className="font-mono text-[10px] tracking-wider text-[#6FB89A]">
            // SOURCE ACTIVITY
          </p>

          <h2
            id="activity-heading"
            className="mt-1 text-sm font-semibold text-[#DDF8EB]"
          >
            Threat activity timeline
          </h2>

          <p className="mt-1 text-xs text-[#8CAFA2]">
            Daily intelligence activity by source
          </p>
        </div>

        <div className="flex rounded border border-[#315648] bg-[#091713] p-1">
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
              className={`rounded px-3 py-1.5 font-mono text-[10px] transition-colors ${
                metric === value
                  ? 'bg-[#1B4A36] text-[#B7F8D8]'
                  : 'text-[#85A99A] hover:text-[#DDF8EB]'
              }`}
            >
              {value === 'observationCount'
                ? 'OBSERVATIONS'
                : 'DISTINCT IOCS'}
            </button>
          ))}
        </div>
      </div>

      <div className="grid gap-3 border-b border-[#294A40] px-5 py-4 sm:grid-cols-3">
        <div>
          <p className="tf-terminal-label">
            TOTAL OBSERVATIONS
          </p>
          <p className="mt-2 font-mono text-xl font-semibold tabular-nums text-[#70EFC0]">
            {numberFormatter.format(data.totalObservations)}
          </p>
        </div>

        <div>
          <p className="tf-terminal-label">
            INTELLIGENCE SOURCES
          </p>
          <p className="mt-2 font-mono text-xl font-semibold tabular-nums text-[#70DDEA]">
            {sources.length}
          </p>
        </div>

        <div>
          <p className="tf-terminal-label">
            ACTIVITY DATES
          </p>
          <p className="mt-2 font-mono text-xl font-semibold tabular-nums text-[#F0C183]">
            {numberFormatter.format(dates.length)}
          </p>
        </div>
      </div>

      {!hasData ? (
        <div className="px-5 py-16 text-center font-mono text-xs text-[#88AD9D]">
          NO DAILY THREAT ACTIVITY DATA AVAILABLE
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

      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[#294A40] bg-[#0D1A1B] px-5 py-3">
        <div className="space-y-1">
          <p className="font-mono text-[10px] text-[#A3D6BD]">
            {dateRange}
          </p>

          <p className="font-mono text-[10px] text-[#789E8E]">
            SOURCE DATES: {data.timezone}. Missing source-date
            records are not treated as zero activity.
          </p>
        </div>

        <time
          dateTime={data.generatedAtUtc}
          className="font-mono text-[10px] text-[#789E8E]"
        >
          GENERATED{' '}
          {new Date(data.generatedAtUtc).toLocaleString()}
        </time>
      </div>
    </section>
  )
}
