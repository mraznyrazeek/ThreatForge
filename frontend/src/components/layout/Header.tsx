
import { useState } from 'react'

import { useAuth } from '../../auth/useAuth'
import type { AppPage } from '../../types/navigation'
import { PAGE_TITLES } from '../../types/navigation'

interface HeaderProps {
  activePage: AppPage
  onMenuClick: () => void
}

const PAGE_PATHS: Record<AppPage, string> = {
  overview: '~/dashboard',
  indicators: '~/intelligence',
  analytics: '~/analytics',
}

export function Header({
  activePage,
  onMenuClick,
}: HeaderProps) {
  const { username, roles, logout } = useAuth()

  const [signingOut, setSigningOut] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const displayName = username ?? 'User'

  const displayRole = roles.includes('administrator')
    ? 'Administrator'
    : roles.includes('analyst')
      ? 'Analyst'
      : 'Authenticated'

  const initials = displayName
    .split(/[-_.\s]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0))
    .join('')
    .toUpperCase()

  async function handleSignOut() {
    if (signingOut) return

    setError(null)
    setSigningOut(true)

    try {
      await logout()
    } catch {
      setError('Unable to sign out. Please try again.')
      setSigningOut(false)
    }
  }

  return (
    <>
      <header className="sticky top-0 z-30 flex min-h-[60px] items-center justify-between gap-3 border-b border-[#25473D] bg-[#0B1417]/95 px-4 backdrop-blur-md sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation"
            aria-controls="main-sidebar"
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded border border-[#31594B] text-[#9CDCC4] hover:bg-[#173027] lg:hidden"
          >
            <svg
              width="17"
              height="17"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
              aria-hidden="true"
            >
              <path d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>

          <div className="hidden font-mono text-[15px] font-semibold text-[#55E8B2] sm:block">
            &gt;_
          </div>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate text-[13px] font-semibold text-[#E7F9F1]">
                {PAGE_TITLES[activePage]}
              </span>

              <span className="hidden rounded border border-[#2C594B] bg-[#102920] px-2 py-0.5 font-mono text-[9px] text-[#79D9AE] sm:inline-flex">
                SOC / INTEL
              </span>
            </div>

            <p className="mt-0.5 hidden font-mono text-[9px] text-[#719C8C] sm:block">
              {PAGE_PATHS[activePage]}
            </p>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <div className="hidden items-center gap-2 border-r border-[#29483D] pr-4 sm:flex">
            <span className="tf-status-dot" />

            <span className="font-mono text-[10px] text-[#91CDB6]">
              SESSION ACTIVE
            </span>
          </div>

          <div className="hidden min-w-0 text-right md:block">
            <p className="max-w-[185px] truncate font-mono text-[10px] font-medium text-[#E1F6EA]">
              {displayName}
            </p>

            <p className="mt-1 font-mono text-[9px] uppercase tracking-wider text-[#70B69C]">
              {displayRole}
            </p>
          </div>

          <div
            title={`${displayName} — ${displayRole}`}
            aria-label={`${displayName}, ${displayRole}`}
            className="flex h-9 w-9 items-center justify-center rounded border border-[#36755C] bg-[#123025] font-mono text-[10px] font-semibold text-[#8BF2C7]"
          >
            {initials || 'TF'}
          </div>

          <button
            type="button"
            disabled={signingOut}
            onClick={() => void handleSignOut()}
            className="inline-flex h-9 items-center gap-2 rounded border border-[#315649] bg-[#12231F] px-3 font-mono text-[10px] font-medium text-[#B9E7D3] transition-colors hover:border-[#65D8A9] hover:bg-[#19382C] disabled:cursor-not-allowed disabled:opacity-50"
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.7"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
              <path d="m16 17 5-5-5-5M21 12H9" />
            </svg>

            <span>
              {signingOut ? 'SIGNING OUT' : 'SIGN OUT'}
            </span>
          </button>
        </div>
      </header>

      {error && (
        <div
          role="alert"
          className="border-b border-[#744346] bg-[#301C21] px-5 py-3 text-xs text-[#FF9FA5]"
        >
          {error}
        </div>
      )}
    </>
  )
}
