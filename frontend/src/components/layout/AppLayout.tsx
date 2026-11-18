
import { useState } from 'react'
import type { ReactNode } from 'react'

import type { AppPage } from '../../types/navigation'

import { Header } from './Header'
import { Sidebar } from './Sidebar'

interface AppLayoutProps {
  children: ReactNode
  activePage: AppPage
  onNavigate: (page: AppPage) => void
}

export function AppLayout({
  children,
  activePage,
  onNavigate,
}: AppLayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] =
    useState(false)

  function handleNavigate(page: AppPage) {
    onNavigate(page)
    setMobileMenuOpen(false)
  }

  function handleCloseMenu() {
    setMobileMenuOpen(false)
  }

  function handleOpenMenu() {
    setMobileMenuOpen(true)
  }

  return (
    <div className="min-h-screen bg-[var(--bg)] text-[var(--text)]">
      <Sidebar
        open={mobileMenuOpen}
        activePage={activePage}
        onNavigate={handleNavigate}
        onClose={handleCloseMenu}
      />

      <div className="relative min-h-screen lg:ml-[244px]">
        <div
          aria-hidden="true"
          className="tf-grid tf-ambient pointer-events-none absolute inset-0"
        />

        <div className="relative z-10 min-h-screen">
          <Header
            activePage={activePage}
            onMenuClick={handleOpenMenu}
          />

          <main
            id="main-content"
            className="mx-auto w-full max-w-[1540px] px-4 py-6 sm:px-6"
          >
            {children}
          </main>
        </div>
      </div>
    </div>
  )
}
