
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
    <div className="min-h-screen bg-[#0E1015] text-[#E7E8ED]">
      <Sidebar
        open={mobileMenuOpen}
        activePage={activePage}
        onNavigate={handleNavigate}
        onClose={handleCloseMenu}
      />

      <div className="min-h-screen lg:ml-[228px]">
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
  )
}
