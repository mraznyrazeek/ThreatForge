
import { useState } from 'react'
import { useAuth } from '../../auth/useAuth'

interface HeaderProps {
  onMenuClick: () => void
}

export function Header({ onMenuClick }: HeaderProps) {
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
      <header className="sticky top-0 z-30 flex h-[52px] items-center justify-between gap-3 border-b border-[#292D37] bg-[#15171D] px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation"
            className="flex h-8 w-8 items-center justify-center rounded-md border border-[#343844] text-[#C8C5D3] hover:bg-[#252833] lg:hidden"
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

          <div className="flex items-center gap-2">
            <span className="font-medium text-[13px] text-[#F0EDF5]">
              Overview
            </span>

            <span className="hidden rounded border border-[#35323F] bg-[#24212F] px-2 py-0.5 font-mono text-[9px] text-[#B2A4D6] sm:inline-flex">
              Intelligence
            </span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <div className="hidden items-center gap-2 border-r border-[#353844] pr-4 sm:flex">
            <span className="h-1.5 w-1.5 rounded-full bg-[#79BBA5]" />
            <span className="font-mono text-[10px] text-[#9499A7]">
              Session active
            </span>
          </div>

          <div className="hidden min-w-0 text-right md:block">
            <p className="max-w-[180px] truncate text-[11px] font-semibold text-[#E6E3EB]">
              {displayName}
            </p>
            <p className="mt-0.5 text-[10px] text-[#8C90A0]">
              {displayRole}
            </p>
          </div>

          <div
            title={`${displayName} — ${displayRole}`}
            className="flex h-8 w-8 items-center justify-center rounded-md border border-[#554C67] bg-[#2B2638] text-[10px] font-semibold text-[#D3C7ED]"
          >
            {initials || 'TF'}
          </div>

          <button
            type="button"
            disabled={signingOut}
            onClick={() => void handleSignOut()}
            className="inline-flex h-8 items-center gap-2 rounded-md border border-[#3A3D48] bg-[#1C1E26] px-3 text-[11px] font-medium text-[#C6C7D1] transition-colors hover:border-[#8F81B8] hover:bg-[#2A2634] hover:text-white disabled:opacity-50"
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
              {signingOut ? 'Signing out' : 'Sign out'}
            </span>
          </button>
        </div>
      </header>

      {error && (
        <div
          role="alert"
          className="border-b border-[#64434A] bg-[#302028] px-5 py-2 text-xs text-[#E7A8B2]"
        >
          {error}
        </div>
      )}
    </>
  )
}
