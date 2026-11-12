
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'
import { AuthProvider } from './auth/AuthProvider'
import { ProtectedApplication } from './auth/ProtectedApplication'

import './index.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <ProtectedApplication>
        <App />
      </ProtectedApplication>
    </AuthProvider>
  </StrictMode>,
)
