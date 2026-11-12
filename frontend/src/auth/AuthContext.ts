
import { createContext } from 'react'

export interface AuthContextValue {
  initialized: boolean
  authenticated: boolean
  username: string | null
  roles: string[]
  error: string | null
  login: () => Promise<void>
  logout: () => Promise<void>
  getAccessToken: () => Promise<string>
}

export const AuthContext = createContext<AuthContextValue | null>(null)
