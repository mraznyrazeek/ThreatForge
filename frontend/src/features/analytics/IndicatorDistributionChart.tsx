
import { useEffect, useMemo, useRef } from 'react'

import * as echarts from 'echarts/core'
import { PieChart } from 'echarts/charts'
import { TooltipComponent } from 'echarts/components'
import { SVGRenderer } from 'echarts/renderers'

import type {
  IndicatorDistributionResponse,
} from '../../types/analytics'

echarts.use([
  PieChart,
  TooltipComponent,
  SVGRenderer,
])

interface IndicatorDistributionChartProps {
  data: IndicatorDistributionResponse
}

const COLORS = [
  '#A999DF',
  '#6DB9B2',
  '#D6A46C',
  '#829DD3',
  '#C78DAF',
  '#8EADC3',
  '#A7A2B8',
  '#C6BA8A',
]

const numberFormatter = new Intl.NumberFormat('en-US')

function formatPercentage(value: number): string {
  return `${value.toFixed(1)}%`
}

export function IndicatorDistributionChart({
  data,
}: IndicatorDistributionChartProps) {
  const chartRef = useRef<HTMLDivElement | null>(null)

  const distribution = useMemo(
    () =>
      [...data.distribution].sort(
        (a, b) => b.count - a.count,
      ),
    [data.distribution],
  )

  const hasData =
    distribution.length > 0 &&
    distribution.some((item) => item.count > 0)

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

      color: COLORS,

      animationDuration: 650,

      tooltip: {
        trigger: 'item',
        backgroundColor: '#222530',
        borderColor: '#454153',
        borderWidth: 1,
        padding: 12,
        textStyle: {
          color: '#E8E5F0',
          fontSize: 12,
        },
        valueFormatter: (value: unknown) =>
          typeof value === 'number'
            ? `${numberFormatter.format(value)} indicators`
            : String(value ?? ''),
      },

      series: [
        {
          name: 'Indicator types',
          type: 'pie',
          radius: ['65%', '84%'],
          center: ['50%', '50%'],
          avoidLabelOverlap: true,
          selectedMode: 'single',

          itemStyle: {
            borderColor: '#191C24',
            borderWidth: 3,
            borderRadius: 5,
          },

          label: {
            show: false,
          },

          emphasis: {
            scale: true,
            scaleSize: 7,
            label: {
              show: false,
            },
          },

          data: distribution.map((item) => ({
            name: item.indicatorType,
            value: item.count,
          })),
        },
      ],
    })

    const resizeObserver = new ResizeObserver(() => {
      chart.resize()
    })

    resizeObserver.observe(element)

    return () => {
      resizeObserver.disconnect()
      chart.dispose()
    }
  }, [distribution, hasData])

  return (
    <section
      aria-labelledby="distribution-heading"
      className="overflow-hidden rounded-lg border border-[#30343F] bg-[#191C24]"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#30343F] px-5 py-4">
        <div>
          <h2
            id="distribution-heading"
            className="text-sm font-semibold text-[#EEEAF5]"
          >
            Indicator distribution
          </h2>

          <p className="mt-1 text-xs text-[#9296A4]">
            Canonical indicators by IOC type
          </p>
        </div>

        <div className="text-right">
          <p className="font-mono text-[10px] uppercase tracking-wider text-[#9296A4]">
            Total indicators
          </p>

          <p className="mt-1 font-mono text-xl font-semibold tabular-nums text-[#EEEAF5]">
            {numberFormatter.format(data.totalIndicators)}
          </p>
        </div>
      </div>

      {!hasData ? (
        <div className="px-5 py-16 text-center text-sm text-[#9296A4]">
          No indicator distribution data available.
        </div>
      ) : (
        <div className="grid gap-5 p-5 xl:grid-cols-[minmax(240px,0.9fr)_minmax(0,1.1fr)]">
          <div className="relative flex min-h-[290px] items-center justify-center">
            <div
              ref={chartRef}
              role="img"
              aria-label="Interactive donut chart of threat indicator types. Exact values are listed alongside the chart."
              className="h-[290px] w-full"
            />

            <div className="pointer-events-none absolute flex flex-col items-center justify-center">
              <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-[#9296A4]">
                IOC Types
              </span>

              <span className="mt-1 text-3xl font-semibold tracking-tight text-[#F0EDF6]">
                {distribution.length}
              </span>

              <span className="mt-1 font-mono text-[10px] text-[#9495A5]">
                Categories
              </span>
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-3 grid grid-cols-[minmax(0,1fr)_auto_auto] gap-3 border-b border-[#30343F] pb-3 font-mono text-[10px] uppercase tracking-wider text-[#7F8493]">
              <span>Indicator type</span>
              <span className="text-right">Count</span>
              <span className="w-14 text-right">Share</span>
            </div>

            <div className="space-y-1">
              {distribution.map((item, index) => (
                <div
                  key={item.indicatorType}
                  className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 rounded-md px-2 py-2.5 transition-colors hover:bg-[#252832]"
                >
                  <div className="flex min-w-0 items-center gap-3">
                    <span
                      aria-hidden="true"
                      className="h-2.5 w-2.5 shrink-0 rounded-sm"
                      style={{
                        backgroundColor:
                          COLORS[index % COLORS.length],
                      }}
                    />

                    <span
                      title={item.indicatorType}
                      className="truncate font-mono text-[11px] text-[#D8D6E2]"
                    >
                      {item.indicatorType}
                    </span>
                  </div>

                  <span className="text-right font-mono text-[11px] tabular-nums text-[#EBE8F2]">
                    {numberFormatter.format(item.count)}
                  </span>

                  <span className="w-14 text-right font-mono text-[11px] tabular-nums text-[#B8A7E1]">
                    {formatPercentage(item.percentage)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#30343F] px-5 py-3">
        <span className="font-mono text-[10px] text-[#858A98]">
          Source: ThreatForge intelligence database
        </span>

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
