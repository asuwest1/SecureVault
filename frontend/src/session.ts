import { QueryClient } from '@tanstack/react-query'

export const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 30_000 } },
})
let controller = new AbortController()
export function sessionSignal() { return controller.signal }
export function resetSession() {
  controller.abort()
  controller = new AbortController()
  queryClient.clear()
}
