
import type { AppPage } from '../../types/navigation'

interface SidebarProps {
  open: boolean
  activePage: AppPage
  onNavigate: (page: AppPage) => void
  onClose: () => void
}

interface NavigationItem {
  id: AppPage
  label: string
  icon: string
}

const navigation: NavigationItem[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: '▦',
  },
  {
    id: 'indicators',
    label: 'Threat Indicators',
    icon: '◇',
  },
  {
    id: 'analytics',
    label: 'Threat Analytics',
    icon: '▥',
  },
]

export function Sidebar({
  open,
  activePage,
  onNavigate,
  onClose,
}: SidebarProps) {
  function navigate(page: AppPage) {
    onNavigate(page)
    onClose()
  }

  return (
    <>
      {open && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={onClose}
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
        />
      )}

      <aside
        id="main-sidebar"
        className={`fixed inset-y-0 left-0 z-50 flex w-[228px] flex-col border-r border-[#292D37] bg-[#15171D] transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-[52px] shrink-0 items-center justify-between border-b border-[#292D37] px-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-[#61547F] bg-[#292338] font-mono text-[11px] font-semibold text-[#C6B8EF]">
              TF
            </div>

            <span className="text-[12px] font-bold tracking-[0.12em] text-[#F0EEF5]">
              THREATFORGE
            </span>
          </div>

          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className="rounded px-2 py-1 text-lg text-[#A3A6B1] hover:bg-[#282B35] lg:hidden"
          >
            ×
          </button>
        </div>

        <nav
          aria-label="Main navigation"
          className="flex-1 px-3 py-5"
        >
          <p className="mb-3 px-3 font-mono text-[9px] font-medium uppercase tracking-[0.16em] text-[#777C89]">
            Workspace
          </p>

          <div className="space-y-1">
            {navigation.map((item) => {
              const active = activePage === item.id

              return (
                <button
                  key={item.id}
                  type="button"
                  aria-current={
                    active ? 'page' : undefined
                  }
                  onClick={() => navigate(item.id)}
                  className={`flex h-10 w-full items-center gap-3 rounded-md border px-3 text-left text-xs font-medium transition-colors ${
                    active
                      ? 'border-[#49405C] bg-[#292435] text-[#D4C8F2]'
                      : 'border-transparent text-[#9296A3] hover:bg-[#22252E] hover:text-[#E2DDEA]'
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`w-5 text-center text-base ${
                      active
                        ? 'text-[#C6B8EF]'
                        : 'text-[#777D89]'
                    }`}
                  >
                    {item.icon}
                  </span>

                  <span className="flex-1">
                    {item.label}
                  </span>
                </button>
              )
            })}
          </div>
        </nav>

        <div className="border-t border-[#292D37] px-4 py-4">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[10px] text-[#7C8190]">
              ThreatForge
            </span>

            <span
              aria-hidden="true"
              className="h-1.5 w-1.5 rounded-full bg-[#A69ACB]"
            />
          </div>
        </div>
      </aside>
    </>
  )
}
