import { useState, useEffect, useRef, useCallback } from 'react'
import { Eye, EyeOff, Clipboard, Check } from 'lucide-react'
import { secretsApi } from '@/api'
import { copyWithAutoClear } from '@/utils/clipboard'

const REVEAL_TIMEOUT_SECONDS = 30

interface RevealButtonProps {
  secretId: string
  onError?: (message: string) => void
}

/**
 * SecureVault RevealButton
 *
 * Security behaviors:
 * 1. Click "Reveal" → GET /secrets/{id}/value
 * 2. Display in masked input (<input type="password">)
 * 3. Secondary click → toggle visibility
 * 4. 30-second countdown → clear value from state
 * 5. Component unmount → clear value from state (navigate-away protection)
 * 6. Copy button → clipboard auto-cleared after 30 seconds
 */
export function RevealButton({ secretId, onError }: RevealButtonProps) {
  const [value, setValue] = useState<string | null>(null)
  const [isVisible, setIsVisible] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [countdown, setCountdown] = useState(0)
  const [copied, setCopied] = useState(false)
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const clearValue = useCallback(() => {
    setValue(null)
    setIsVisible(false)
    setCountdown(0)
    if (countdownRef.current) {
      clearInterval(countdownRef.current)
      countdownRef.current = null
    }
  }, [])

  // CRITICAL: Zero the value on unmount — protects against navigate-away
  useEffect(() => {
    return () => {
      clearValue()
    }
  }, [clearValue])

  const startCountdown = useCallback(() => {
    setCountdown(REVEAL_TIMEOUT_SECONDS)
    countdownRef.current = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearValue()
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }, [clearValue])

  const handleReveal = useCallback(async () => {
    if (value !== null) {
      // Toggle visibility on second click
      setIsVisible((v) => !v)
      return
    }

    setIsLoading(true)
    try {
      const result = await secretsApi.getValue(secretId)
      setValue(result.value)
      setIsVisible(false)  // Masked by default
      startCountdown()
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to reveal secret'
      onError?.(message)
    } finally {
      setIsLoading(false)
    }
  }, [value, secretId, startCountdown, onError])

  const handleCopy = useCallback(async () => {
    if (!value) return
    await copyWithAutoClear(value, REVEAL_TIMEOUT_SECONDS)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }, [value])

  if (value !== null) {
    return (
      <div className="flex items-center gap-2">
        <div className="relative flex items-center">
          {/* All user content rendered safely through React — no dangerouslySetInnerHTML */}
          <input
            type={isVisible ? 'text' : 'password'}
            value={value}
            readOnly
            className="font-mono text-sm bg-muted px-3 py-1.5 rounded border border-border
                       min-w-[200px] max-w-[400px] pr-10"
            aria-label="Secret value"
          />
          <button
            onClick={() => setIsVisible((v) => !v)}
            className="absolute right-2 text-muted-foreground hover:text-foreground"
            aria-label={isVisible ? 'Hide value' : 'Show value'}
          >
            {isVisible ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        </div>

        <button
          onClick={handleCopy}
          className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground"
          aria-label="Copy to clipboard"
        >
          {copied ? <Check size={16} className="text-green-500" /> : <Clipboard size={16} />}
        </button>

        <div className="flex items-center gap-1 text-xs text-muted-foreground">
          <span>Clears in {countdown}s</span>
          <button
            onClick={clearValue}
            className="text-destructive hover:underline ml-1"
            aria-label="Clear secret value"
          >
            Clear
          </button>
        </div>
      </div>
    )
  }

  return (
    <button
      onClick={handleReveal}
      disabled={isLoading}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm
                 bg-primary text-primary-foreground rounded hover:bg-primary/90
                 disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <Eye size={14} />
      {isLoading ? 'Loading...' : 'Reveal'}
    </button>
  )
}
