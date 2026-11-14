
import { lazy, Suspense, useState } from 'react'

import { AppLayout } from './components/layout/AppLayout'
import { OverviewPage } from './features/overview/OverviewPage'
import { IndicatorsPage } from './features/indicators/IndicatorsPage'

import type { AppPage } from './types/navigation'

const AnalyticsPage = lazy(async () => {
  const module = await import(
    './features/analytics/AnalyticsPage'
  )

  return {
    default: module.AnalyticsPage,
  }
})

function AnalyticsLoading() {
  return (
    <div
      role="status"
      className="flex min-h-[280px] items-center justify-center gap-3 rounded-lg border border-[#30343F] bg-[#191C24]"
    >
      <span
        aria-hidden="true"
        className="h-5 w-5 animate-spin rounded-full border-2 border-[#514562] border-t-[#B6A0EF]"
      />

      <span className="font-mono text-xs text-[#A7A2B8]">
        Loading threat analytics...
      </span>
    </div>
  )
}

function App() {
  const [activePage, setActivePage] =
    useState<AppPage>('overview')

  return (
    <AppLayout
      activePage={activePage}
      onNavigate={setActivePage}
    >
      {activePage === 'overview' && (
        <OverviewPage />
      )}

      {activePage === 'indicators' && (
        <IndicatorsPage />
      )}

      {activePage === 'analytics' && (
        <Suspense fallback={<AnalyticsLoading />}>
          <AnalyticsPage />
        </Suspense>
      )}
    </AppLayout>
  )
}

export default App
