import { useEffect, useRef, useCallback } from 'react'

const IDLE_EVENTS = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'] as const

/**
 * Fires `onIdle` after `timeoutMs` of inactivity.
 * Resets the timer on any user interaction.
 */
export function useIdleTimeout(onIdle: () => void, timeoutMs = 15 * 60 * 1000): void {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const onIdleRef = useRef(onIdle)
  onIdleRef.current = onIdle  // Keep ref current without re-registering listeners

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      onIdleRef.current()
    }, timeoutMs)
  }, [timeoutMs])

  useEffect(() => {
    // Start timer immediately
    resetTimer()

    IDLE_EVENTS.forEach((event) =>
      window.addEventListener(event, resetTimer, { passive: true })
    )

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      IDLE_EVENTS.forEach((event) =>
        window.removeEventListener(event, resetTimer)
      )
    }
  }, [resetTimer])
}
