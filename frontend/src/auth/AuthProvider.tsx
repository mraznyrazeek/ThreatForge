
import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'
import type { ReactNode } from 'react'
import { AuthContext } from './AuthContext'
import {
  initializeKeycloak,
  keycloak,
} from './keycloak'

interface AuthProviderProps {
  children: ReactNode
}

const allowedRoles = new Set([
  'analyst',
  'administrator',
])

export function AuthProvider({
  children,
}: AuthProviderProps) {
  const [initialized, setInitialized] = useState(false)
  const [authenticated, setAuthenticated] = useState(false)
  const [username, setUsername] = useState<string | null>(null)
  const [roles, setRoles] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)

  const synchronizeAuthentication = useCallback(() => {
    const isAuthenticated = keycloak.authenticated === true

    setAuthenticated(isAuthenticated)

    if (!isAuthenticated) {
      setUsername(null)
      setRoles([])
      return
    }

    setUsername(
      keycloak.tokenParsed?.preferred_username ?? null,
    )

    const clientRoles =
      keycloak.resourceAccess?.['threatforge-api']?.roles ?? []

    setRoles(
      clientRoles.filter((role) => allowedRoles.has(role)),
    )
  }, [])

  useEffect(() => {
    let active = true

    const synchronize = () => {
      if (!active) return

      synchronizeAuthentication()
    }

    keycloak.onAuthSuccess = synchronize
    keycloak.onAuthRefreshSuccess = synchronize
    keycloak.onAuthLogout = synchronize

    keycloak.onAuthError = () => {
      if (!active) return

      setAuthenticated(false)
      setUsername(null)
      setRoles([])
      setError('Keycloak authentication failed.')
    }

    keycloak.onAuthRefreshError = () => {
      if (!active) return

      setAuthenticated(false)
      setUsername(null)
      setRoles([])
      setError(
        'Your authentication session could not be refreshed.',
      )
    }

    keycloak.onTokenExpired = () => {
      void keycloak.updateToken(30).catch(() => {
        if (!active) return

        setAuthenticated(false)
        setUsername(null)
        setRoles([])
        setError(
          'Your authentication session has expired.',
        )
      })
    }

    initializeKeycloak()
      .then(() => {
        if (!active) return

        synchronizeAuthentication()
        setError(null)
        setInitialized(true)
      })
      .catch((initializationError: unknown) => {
        console.error(
          'Keycloak initialization failed:',
          initializationError,
        )

        if (!active) return

        setAuthenticated(false)
        setUsername(null)
        setRoles([])
        setError(
          'Unable to connect to the identity provider. ' +
          'Verify that Keycloak is running and reload the page.',
        )
        setInitialized(true)
      })

    return () => {
      active = false

      keycloak.onAuthSuccess = undefined
      keycloak.onAuthRefreshSuccess = undefined
      keycloak.onAuthLogout = undefined
      keycloak.onAuthError = undefined
      keycloak.onAuthRefreshError = undefined
      keycloak.onTokenExpired = undefined
    }
  }, [synchronizeAuthentication])

  const login = useCallback(async () => {
    await keycloak.login({
      redirectUri: `${window.location.origin}/`,
    })
  }, [])

  const logout = useCallback(async () => {
    await keycloak.logout({
      redirectUri: `${window.location.origin}/`,
    })
  }, [])

  const getAccessToken =
    useCallback(async (): Promise<string> => {
      if (!keycloak.authenticated) {
        throw new Error('User is not authenticated.')
      }

      try {
        await keycloak.updateToken(30)
      } catch {
        throw new Error(
          'Unable to refresh the access token. ' +
          'Please sign in again.',
        )
      }

      if (!keycloak.token) {
        throw new Error('No access token is available.')
      }

      return keycloak.token
    }, [])

  const value = useMemo(
    () => ({
      initialized,
      authenticated,
      username,
      roles,
      error,
      login,
      logout,
      getAccessToken,
    }),
    [
      initialized,
      authenticated,
      username,
      roles,
      error,
      login,
      logout,
      getAccessToken,
    ],
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}
