
import { useEffect, useRef } from 'react'
import { createPortal } from 'react-dom'

import type {
  IndicatorDetailResponse,
} from '../../types/indicatorDetail'

import { IndicatorInvestigationPanel } from './IndicatorInvestigationPanel'

interface IndicatorInvestigationModalProps {
  indicatorId: number
  data: IndicatorDetailResponse | null
  loading: boolean
  error: string | null
  onClose: () => void
}

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ')

export function IndicatorInvestigationModal({
  indicatorId,
  data,
  loading,
  error,
  onClose,
}: IndicatorInvestigationModalProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    const previousFocus = document.activeElement
    const previousOverflow = document.body.style.overflow

    document.body.style.overflow = 'hidden'

    dialogRef.current?.focus()

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        event.preventDefault()
        onClose()
        return
      }

      if (event.key !== 'Tab') return

      const dialog = dialogRef.current

      if (!dialog) return

      const focusable = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          FOCUSABLE_SELECTOR,
        ),
      ).filter(
        (element) =>
          element.getClientRects().length > 0,
      )

      if (focusable.length === 0) {
        event.preventDefault()
        dialog.focus()
        return
      }

      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const current = document.activeElement

      if (event.shiftKey) {
        if (current === first || current === dialog) {
          event.preventDefault()
          last.focus()
        }
      } else if (
        current === last ||
        current === dialog
      ) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener(
      'keydown',
      handleKeyDown,
    )

    return () => {
      document.removeEventListener(
        'keydown',
        handleKeyDown,
      )

      document.body.style.overflow = previousOverflow

      if (
        previousFocus instanceof HTMLElement &&
        previousFocus.isConnected
      ) {
        previousFocus.focus()
      }
    }
  }, [onClose])

  return createPortal(
    <div
      className="fixed inset-0 z-[100] flex items-center justify-center bg-[#020807]/85 p-2 backdrop-blur-[5px] sm:p-5"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) {
          onClose()
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="investigation-heading"
        aria-describedby="investigation-dialog-description"
        tabIndex={-1}
        className="max-h-[calc(100dvh-1rem)] w-full max-w-4xl overflow-x-hidden overflow-y-auto overscroll-contain rounded border border-[#43896B] bg-[#101A1D] shadow-[0_24px_100px_rgba(0,0,0,0.7),0_0_45px_rgba(81,233,181,0.08)] outline-none focus-visible:ring-2 focus-visible:ring-[#51E9B5] sm:max-h-[calc(100dvh-2.5rem)]"
      >
        <p
          id="investigation-dialog-description"
          className="sr-only"
        >
          Threat indicator investigation. Press Escape or
          use the Close button to return to the indicator
          inventory.
        </p>

        <IndicatorInvestigationPanel
          indicatorId={indicatorId}
          data={data}
          loading={loading}
          error={error}
          onClose={onClose}
        />
      </div>
    </div>,
    document.body,
  )
}
