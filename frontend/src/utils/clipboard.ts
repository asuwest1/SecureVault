/**
 * Copies a value to the clipboard and automatically clears it after `seconds`.
 * Clearing is best-effort — clipboard API may be unavailable on page unload.
 */
export async function copyWithAutoClear(value: string, seconds = 30): Promise<void> {
  await navigator.clipboard.writeText(value)

  setTimeout(async () => {
    try {
      // Only clear if our value is still in the clipboard (user may have copied something else)
      const current = await navigator.clipboard.readText().catch(() => null)
      if (current === value) {
        await navigator.clipboard.writeText('')
      }
    } catch {
      // Clipboard access denied on some browsers — this is acceptable
    }
  }, seconds * 1000)
}
