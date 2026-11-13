
type SidebarProps = {
  open: boolean
  onClose: () => void
}

export function Sidebar({ open, onClose }: SidebarProps) {
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
        className={`fixed inset-y-0 left-0 z-50 flex w-[228px] flex-col border-r border-[#292D37] bg-[#15171D] transition-transform duration-200 lg:translate-x-0 ${
          open ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-14 items-center justify-between border-b border-[#292D37] px-5">
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
            className="text-lg text-[#A3A6B1] lg:hidden"
          >
            ×
          </button>
        </div>

        <nav
          aria-label="Main navigation"
          className="flex-1 px-3 py-6"
        >
          <p className="mb-3 px-3 font-mono text-[9px] font-medium uppercase tracking-[0.16em] text-[#676D7A]">
            Workspace
          </p>

          <button
            type="button"
            aria-current="page"
            onClick={onClose}
            className="flex h-10 w-full items-center gap-3 rounded-md border border-[#403950] bg-[#292435] px-3 text-left text-xs font-medium text-[#D4C8F2]"
          >
            <span aria-hidden="true" className="text-base">
              ◫
            </span>
            Overview
          </button>

          <div className="mt-1 flex h-10 items-center gap-3 rounded-md px-3 text-xs text-[#777D89]">
            <span aria-hidden="true" className="text-base">
              ◈
            </span>
            <span className="flex-1">Indicators</span>
            <span className="font-mono text-[9px] text-[#626775]">
              SOON
            </span>
          </div>

          <div className="mt-1 flex h-10 items-center gap-3 rounded-md px-3 text-xs text-[#777D89]">
            <span aria-hidden="true" className="text-base">
              ▥
            </span>
            <span className="flex-1">Analytics</span>
            <span className="font-mono text-[9px] text-[#626775]">
              SOON
            </span>
          </div>
        </nav>

        <div className="border-t border-[#292D37] px-5 py-4">
          <p className="font-mono text-[10px] text-[#727784]">
            ThreatForge
          </p>
        </div>
      </aside>
    </>
  )
}
