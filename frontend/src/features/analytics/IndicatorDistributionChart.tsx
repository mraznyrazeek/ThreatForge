
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
  '#51E9B5',
  '#61D8EB',
  '#F3B66A',
  '#91A9FF',
  '#E78FB0',
  '#A3D4C4',
  '#C4A4F3',
  '#D5C18B',
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

    if (!element || !hasData) return

    const chart = echarts.init(element, undefined, {
      renderer: 'svg',
    })

    chart.setOption({
      backgroundColor: 'transparent',
      color: COLORS,
      animationDuration: 650,

      tooltip: {
        trigger: 'item',
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
            borderColor: '#101A1D',
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

    const observer = new ResizeObserver(() => {
      chart.resize()
    })

    observer.observe(element)

    return () => {
      observer.disconnect()
      chart.dispose()
    }
  }, [distribution, hasData])

  return (
    <section
      aria-labelledby="distribution-heading"
      className="tf-glow-border overflow-hidden rounded border border-[#2C5749] bg-[#101A1D]"
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-[#294A40] bg-[#0D1A1B] px-5 py-4">
        <div>
          <p className="font-mono text-[10px] tracking-wider text-[#6FB89A]">
            // IOC COMPOSITION
          </p>

          <h2
            id="distribution-heading"
            className="mt-1 text-sm font-semibold text-[#DDF8EB]"
          >
            Indicator distribution
          </h2>

          <p className="mt-1 text-xs text-[#8CAFA2]">
            Canonical indicators by IOC type
          </p>
        </div>

        <div className="text-right">
          <p className="tf-terminal-label">
            TOTAL INDICATORS
          </p>

          <p className="mt-2 font-mono text-xl font-semibold tabular-nums text-[#70EFC0]">
            {numberFormatter.format(data.totalIndicators)}
          </p>
        </div>
      </div>

      {!hasData ? (
        <div className="px-5 py-16 text-center font-mono text-xs text-[#88AD9D]">
          NO INDICATOR DISTRIBUTION DATA AVAILABLE
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
              <span className="font-mono text-[10px] tracking-[0.15em] text-[#80B5A1]">
                IOC TYPES
              </span>

              <span className="mt-1 font-mono text-3xl font-semibold text-[#DFFFEF]">
                {distribution.length}
              </span>

              <span className="mt-1 font-mono text-[10px] text-[#739E8E]">
                CATEGORIES
              </span>
            </div>
          </div>

          <div className="min-w-0">
            <div className="mb-3 grid grid-cols-[minmax(0,1fr)_auto_auto] gap-3 border-b border-[#294A40] pb-3 font-mono text-[10px] tracking-wider text-[#83B6A4]">
              <span>INDICATOR TYPE</span>
              <span className="text-right">COUNT</span>
              <span className="w-14 text-right">SHARE</span>
            </div>

            <div className="space-y-1">
              {distribution.map((item, index) => (
                <div
                  key={item.indicatorType}
                  className="grid grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 rounded px-2 py-2.5 transition-colors hover:bg-[#173028]"
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
                      className="truncate font-mono text-[11px] text-[#CDEBDE]"
                    >
                      {item.indicatorType}
                    </span>
                  </div>

                  <span className="text-right font-mono text-[11px] tabular-nums text-[#E1F9EC]">
                    {numberFormatter.format(item.count)}
                  </span>

                  <span className="w-14 text-right font-mono text-[11px] tabular-nums text-[#75E5B6]">
                    {formatPercentage(item.percentage)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-[#294A40] bg-[#0D1A1B] px-5 py-3">
        <span className="font-mono text-[10px] text-[#789E8E]">
          SOURCE: THREATFORGE INTELLIGENCE DATABASE
        </span>

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
