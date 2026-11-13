
import { useState } from 'react'
import type { ReactNode } from 'react'
import { useAuth } from './useAuth'

interface ProtectedApplicationProps {
  children: ReactNode
}

const permittedRoles = ['analyst', 'administrator']

export function ProtectedApplication({
  children,
}: ProtectedApplicationProps) {
  const {
    initialized,
    authenticated,
    username,
    roles,
    error,
    login,
    logout,
  } = useAuth()

  const [actionError, setActionError] = useState<string | null>(
    null,
  )

  const hasAccess = roles.some((role) =>
    permittedRoles.includes(role),
  )

  const handleLogin = async () => {
    setActionError(null)

    try {
      await login()
    } catch {
      setActionError('Unable to start Keycloak login.')
    }
  }

  const handleLogout = async () => {
    setActionError(null)

    try {
      await logout()
    } catch {
      setActionError('Unable to complete logout.')
    }
  }

  if (!initialized) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#0b111a] p-6 text-slate-200">
        <div
          className="flex flex-col items-center gap-5"
          role="status"
        >
          <div className="h-10 w-10 animate-spin rounded-full border-2 border-cyan-400/20 border-t-cyan-400" />
          <p className="font-mono text-xs tracking-widest text-slate-400">
            INITIALIZING THREATFORGE SECURITY
          </p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0b111a] p-6 text-slate-200">
        <section className="w-full max-w-md rounded-xl border border-red-400/20 bg-[#131c27] p-8">
          <p className="font-mono text-xs tracking-widest text-red-400">
            AUTHENTICATION ERROR
          </p>
          <h1 className="mt-4 text-2xl font-bold">
            Security service unavailable
          </h1>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            {error}
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="mt-7 rounded-md bg-cyan-400 px-5 py-3 text-sm font-semibold text-slate-950 hover:bg-cyan-300"
          >
            Retry connection
          </button>
        </section>
      </main>
    )
  }

  if (!authenticated) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0b111a] p-5 text-slate-200">
        <section className="w-full max-w-md overflow-hidden rounded-xl border border-cyan-400/15 bg-[#131c27] shadow-2xl shadow-black/30">
          <div className="border-b border-white/10 bg-cyan-400/5 px-8 py-7">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-lg border border-cyan-400/30 bg-cyan-400/10 font-mono text-xl font-bold text-cyan-400">
                TF
              </div>
              <div>
                <h1 className="text-xl font-bold tracking-wider text-white">
                  THREAT<span className="text-cyan-400">FORGE</span>
                </h1>
                <p className="mt-1 font-mono text-[10px] tracking-widest text-slate-400">
                  THREAT INTELLIGENCE PLATFORM
                </p>
              </div>
            </div>
          </div>

          <div className="px-8 py-9">
            <p className="font-mono text-[11px] tracking-widest text-cyan-400">
              SECURE ACCESS
            </p>
            <h2 className="mt-4 text-2xl font-semibold text-white">
              Sign in to ThreatForge
            </h2>
            <p className="mt-3 text-sm leading-7 text-slate-400">
              Authenticate with your Keycloak account to
              access protected threat intelligence and analytics.
            </p>

            <button
              type="button"
              onClick={() => void handleLogin()}
              className="mt-8 w-full rounded-md bg-cyan-400 px-5 py-3 text-sm font-bold text-slate-950 transition-colors hover:bg-cyan-300"
            >
              Sign in with Keycloak
            </button>

            {actionError && (
              <p role="alert" className="mt-4 text-sm text-red-400">
                {actionError}
              </p>
            )}

            <p className="mt-7 text-center font-mono text-[10px] text-slate-500">
              AUTHORIZATION CODE + PKCE S256
            </p>
          </div>
        </section>
      </main>
    )
  }

  if (!hasAccess) {
    return (
      <main className="flex min-h-screen items-center justify-center bg-[#0b111a] p-6 text-slate-200">
        <section className="w-full max-w-md rounded-xl border border-orange-400/20 bg-[#131c27] p-8">
          <p className="font-mono text-xs tracking-widest text-orange-400">
            ACCESS DENIED
          </p>
          <h1 className="mt-4 text-2xl font-bold text-white">
            Insufficient permissions
          </h1>
          <p className="mt-4 text-sm leading-7 text-slate-400">
            You are authenticated as{' '}
            <strong className="text-white">
              {username ?? 'Unknown user'}
            </strong>
            , but your account does not have an approved
            ThreatForge API role.
          </p>
          <p className="mt-3 text-sm text-slate-400">
            Required role: analyst or administrator.
          </p>

          <button
            type="button"
            onClick={() => void handleLogout()}
            className="mt-7 rounded-md border border-slate-600 px-5 py-3 text-sm font-medium text-white hover:bg-white/10"
          >
            Sign out
          </button>

          {actionError && (
            <p role="alert" className="mt-4 text-sm text-red-400">
              {actionError}
            </p>
          )}
        </section>
      </main>
    )
  }

  
  return <>{children}</>
}

