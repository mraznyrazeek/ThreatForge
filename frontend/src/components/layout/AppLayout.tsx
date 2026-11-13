
import { useState } from 'react'
import type { ReactNode } from 'react'
import { Header } from './Header'
import { Sidebar } from './Sidebar'

type AppLayoutProps = {
  children: ReactNode
}

export function AppLayout({ children }: AppLayoutProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-[#0E1015] text-[#E7E8ED]">
      <Sidebar
        open={mobileMenuOpen}
        onClose={() => setMobileMenuOpen(false)}
      />

      <div className="min-h-screen lg:ml-[228px]">
        <Header
          onMenuClick={() => setMobileMenuOpen(true)}
        />

        <main className="mx-auto w-full max-w-[1540px] px-4 py-6 sm:px-6">
          {children}
        </main>
      </div>
    </div>
  )
}
