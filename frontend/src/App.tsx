
import { useState } from 'react'

import { AppLayout } from './components/layout/AppLayout'
import { OverviewPage } from './features/overview/OverviewPage'
import { IndicatorsPage } from './features/indicators/IndicatorsPage'

import type { AppPage } from './types/navigation'

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
    </AppLayout>
  )
}

export default App
