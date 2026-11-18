
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
  path: string
  icon: string
}

const navigation: NavigationItem[] = [
  {
    id: 'overview',
    label: 'Overview',
    path: '/dashboard',
    icon: '▦',
  },
  {
    id: 'indicators',
    label: 'Threat Indicators',
    path: '/intelligence',
    icon: '◇',
  },
  {
    id: 'analytics',
    label: 'Threat Analytics',
    path: '/analytics',
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
          className="fixed inset-0 z-40 bg-black/75 lg:hidden"
        />
      )}

      <aside
        id="main-sidebar"
        className={`fixed inset-y-0 left-0 z-50 flex w-[244px] flex-col border-r border-[#29453F] bg-[#0B1316] shadow-[8px_0_35px_rgba(0,0,0,0.18)] transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand */}
        <div className="flex h-[60px] shrink-0 items-center justify-between border-b border-[#243D37] px-4">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded border border-[#367D67] bg-[#102A23] shadow-[0_0_16px_rgba(81,233,181,0.12)]">
              <span className="font-mono text-[12px] font-semibold text-[#72F2C5]">
                TF
              </span>
            </div>

            <div className="min-w-0">
              <p className="text-[12px] font-bold tracking-[0.13em] text-[#E5FFF3]">
                THREATFORGE
              </p>

              <p className="mt-0.5 font-mono text-[9px] tracking-[0.12em] text-[#61BDA0]">
                SECURITY INTELLIGENCE
              </p>
            </div>
          </div>

          <button
            type="button"
            aria-label="Close navigation"
            onClick={onClose}
            className="rounded px-2 py-1 text-lg text-[#9ABDB0] hover:bg-[#183027] lg:hidden"
          >
            ×
          </button>
        </div>

        {/* Terminal identity */}
        <div className="border-b border-[#20342F] bg-[#0A1716] px-5 py-4">
          <div className="flex items-center gap-2">
            <span className="tf-status-dot" />

            <span className="font-mono text-[10px] text-[#86DDBB]">
              SOC WORKSPACE
            </span>
          </div>

          <p className="mt-2 font-mono text-[10px] text-[#769B90]">
            operator@threatforge:~$
          </p>
        </div>

        {/* Navigation */}
        <nav
          aria-label="Main navigation"
          className="flex-1 px-3 py-5"
        >
          <p className="mb-3 px-3 font-mono text-[9px] font-medium uppercase tracking-[0.2em] text-[#6A9586]">
            // Modules
          </p>

          <div className="space-y-1.5">
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
                  className={`group relative flex w-full items-center gap-3 rounded border px-3 py-3 text-left transition-all ${
                    active
                      ? 'border-[#32745D] bg-[#112A23] shadow-[inset_3px_0_0_#51E9B5,0_0_14px_rgba(81,233,181,0.07)]'
                      : 'border-transparent hover:border-[#2C4B42] hover:bg-[#14221F]'
                  }`}
                >
                  <span
                    aria-hidden="true"
                    className={`w-5 shrink-0 text-center font-mono text-base ${
                      active
                        ? 'text-[#64EFC0]'
                        : 'text-[#6C9E8F] group-hover:text-[#A1EAD2]'
                    }`}
                  >
                    {item.icon}
                  </span>

                  <span className="min-w-0 flex-1">
                    <span
                      className={`block text-xs font-medium ${
                        active
                          ? 'text-[#D9FFEE]'
                          : 'text-[#9EB9AF] group-hover:text-[#E0F9EF]'
                      }`}
                    >
                      {item.label}
                    </span>

                    <span
                      className={`mt-1 block font-mono text-[9px] ${
                        active
                          ? 'text-[#78BDA1]'
                          : 'text-[#577C71]'
                      }`}
                    >
                      {item.path}
                    </span>
                  </span>

                  {active && (
                    <span
                      aria-hidden="true"
                      className="h-1.5 w-1.5 rounded-full bg-[#51E9B5] shadow-[0_0_8px_#51E9B5]"
                    />
                  )}
                </button>
              )
            })}
          </div>
        </nav>

        {/* Footer */}
        <div className="border-t border-[#243D37] bg-[#0A1516] px-4 py-4">
          <div className="flex items-center justify-between">
            <span className="font-mono text-[9px] tracking-wide text-[#749B8F]">
              THREATFORGE / SOC
            </span>

            <span className="tf-status-dot" />
          </div>

          <p className="mt-2 font-mono text-[9px] text-[#55796E]">
            Intelligence operations console
          </p>
        </div>
      </aside>
    </>
  )
}
