
import { OverviewPage } from './features/overview/OverviewPage'

function App() {
  return (
    <div className="min-h-screen bg-[#0e1015] text-[#e7e8ed]">
      <header className="border-b border-[#292d37] bg-[#14161c]">
        <div className="mx-auto flex h-14 max-w-[1380px] items-center justify-between px-5 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-md border border-[#554c75] bg-[#28243a] font-mono text-xs font-semibold text-[#c4b7ec]">
              TF
            </div>

            <span className="text-[13px] font-bold tracking-[0.1em] text-[#f1f0f5]">
              THREATFORGE
            </span>

            <span className="hidden h-4 w-px bg-[#383c48] sm:block" />

            <span className="hidden font-mono text-[10px] text-[#818695] sm:block">
              Intelligence
            </span>
          </div>

          <div className="flex items-center gap-2 font-mono text-[10px] text-[#858b99]">
            <span className="h-1.5 w-1.5 rounded-full bg-[#79bba5]" />
            <span>Workspace</span>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1380px] px-5 py-7 lg:px-8">
        <OverviewPage />
      </main>
    </div>
  )
}

export default App
