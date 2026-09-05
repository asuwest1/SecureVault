const { test, afterEach } = require('node:test')
const assert = require('node:assert/strict')
const { buildSync } = require('esbuild')
const Module = require('node:module')
const path = require('node:path')
const source = buildSync({
  stdin: { contents: `export { apiRequest, silentRefresh } from './src/api'; export { useAuthStore } from './src/stores/authStore'; export { queryClient, sessionSignal } from './src/session';`, resolveDir: process.cwd() },
  bundle: true, platform: 'node', format: 'cjs', write: false,
  tsconfig: 'tsconfig.json',
}).outputFiles[0].text
const moduleUnderTest = new Module(path.join(process.cwd(), 'tests', 'compiled.cjs'))
moduleUnderTest.paths = module.paths
moduleUnderTest._compile(source, path.join(process.cwd(), 'tests', 'compiled.cjs'))
const { apiRequest, silentRefresh, useAuthStore, queryClient, sessionSignal } = moduleUnderTest.exports
const originalFetch = global.fetch
const payload = id => ({ sub: id, name: id, is_super_admin: 'false', role_ids: [], exp: Math.floor(Date.now() / 1000) + 900 })
const token = id => `header.${Buffer.from(JSON.stringify(payload(id))).toString('base64url')}.signature`
afterEach(() => { useAuthStore.getState().clearAuth(); global.fetch = originalFetch })

test('DELETE retry accepts 204 after successful refresh', async () => {
  useAuthStore.getState().setAuth(token('a'), payload('a'))
  const responses = [new Response('{}', { status: 401 }), new Response(JSON.stringify({ accessToken: token('a') })), new Response(null, { status: 204 })]
  global.fetch = async () => responses.shift()
  assert.equal(await apiRequest('/secrets/id', { method: 'DELETE' }), undefined)
  assert.equal(responses.length, 0)
})
test('empty logout response is accepted', async () => {
  global.fetch = async () => new Response(null, { status: 200 })
  assert.equal(await apiRequest('/auth/logout', { method: 'POST' }), undefined)
})
test('logout cancels requests and removes prior user data', () => {
  useAuthStore.getState().setAuth(token('a'), payload('a'))
  queryClient.setQueryData(['secret', 'id'], { notes: 'private' })
  const signal = sessionSignal()
  useAuthStore.getState().clearAuth()
  assert.equal(signal.aborted, true)
  assert.equal(queryClient.getQueryData(['secret', 'id']), undefined)
})
test('account switch removes old cache without requiring logout', () => {
  useAuthStore.getState().setAuth(token('a'), payload('a'))
  queryClient.setQueryData(['secrets'], ['private'])
  useAuthStore.getState().setAuth(token('b'), payload('b'))
  assert.equal(queryClient.getQueryData(['secrets']), undefined)
})
test('late refresh response cannot resurrect a logged out session', async () => {
  useAuthStore.getState().setAuth(token('a'), payload('a'))
  let complete
  global.fetch = () => new Promise(resolve => { complete = resolve })
  const refreshing = silentRefresh()
  useAuthStore.getState().clearAuth()
  complete(new Response(JSON.stringify({ accessToken: token('a') })))
  assert.equal(await refreshing, false)
  assert.equal(useAuthStore.getState().accessToken, null)
})
test('invalid credentials do not refresh or retry login', async () => {
  let calls = 0
  global.fetch = async () => { calls++; return new Response('{}', { status: 401 }) }
  await assert.rejects(apiRequest('/auth/login', { method: 'POST' }))
  assert.equal(calls, 1)
})
