/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
  useSearch,
} from '@tanstack/react-router'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ManagedAccountBoundary } from '@/features/keys/components/managed-account-boundary'
import type { ManagedAccountContext } from '@/features/keys/types'
import { api } from '@/lib/api'
import { modelWorkspaceSearchSchema } from '@/lib/model-workspace'
import { useAuthStore } from '@/stores/auth-store'
import { useSystemConfigStore } from '@/stores/system-config-store'

import { getUserQuotaDates, getFlowQuotaDates } from '../../../api'
import { LogStatCards } from '../../models/log-stat-cards'
import { OverviewDashboard } from '../overview-dashboard'

const storageKey = 'dashboard_overview_setup_guide_expanded'
let client: QueryClient
let keyLookupError: Error | null

beforeEach(() => {
  window.localStorage.clear()
  useSystemConfigStore.setState(useSystemConfigStore.getInitialState(), true)
  useAuthStore.getState().auth.setUser({
    id: 1,
    username: 'dashboard-user',
    role: 1,
    quota: 1000000,
    used_quota: 1000,
    request_count: 1,
  })
  client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  keyLookupError = null
  vi.spyOn(api, 'get').mockImplementation(async (url) => {
    switch (url) {
      case '/api/token/?p=1&size=10':
        if (keyLookupError) throw keyLookupError
        return {
          data: {
            success: true,
            data: {
              items: [{ id: 1, name: 'App key', key: 'masked', status: 1 }],
            },
          },
        }
      case '/api/status':
        return {
          data: {
            data: {
              api_info_enabled: false,
              announcements_enabled: false,
              faq_enabled: false,
              uptime_kuma_enabled: false,
            },
          },
        }
      case '/api/user/models':
        return { data: { success: true, data: ['gpt-4o-mini'] } }
      case '/api/data/self':
        return { data: { success: true, data: [] } }
      default:
        throw new Error(`Unexpected dashboard request: ${url}`)
    }
  })
})

afterEach(() => {
  cleanup()
  client.clear()
  useAuthStore.setState(useAuthStore.getInitialState(), true)
  useSystemConfigStore.setState(useSystemConfigStore.getInitialState(), true)
  window.localStorage.clear()
})

function ScopedOverview() {
  const workspaceKey = useSearch({ strict: false }).workspace_key
  return (
    <ManagedAccountBoundary
      workspaceKey={workspaceKey}
      action='model.usage.read'
    >
      {(account, scopeKey) => (
        <OverviewDashboard
          workspaceKey={workspaceKey}
          account={account}
          scopeKey={scopeKey}
        />
      )}
    </ManagedAccountBoundary>
  )
}

async function renderOverview(workspaceKey?: string) {
  const router = createRouter({
    routeTree: createRootRoute({
      component: workspaceKey ? ScopedOverview : OverviewDashboard,
      validateSearch: modelWorkspaceSearchSchema,
    }),
    history: createMemoryHistory({
      initialEntries: [
        workspaceKey
          ? `/?workspace_key=${encodeURIComponent(workspaceKey)}`
          : '/',
      ],
    }),
  })
  await router.load()
  const view = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
  return { ...view, router }
}

describe('overview setup guide', () => {
  it('shows usage first and only a header entry when setup is complete', async () => {
    await renderOverview()

    const toggle = await screen.findByRole('button', { name: 'Setup guide' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(
      screen.getAllByRole('heading').map((heading) => heading.textContent)
    ).toEqual(['Overview', 'Usage at a glance'])
    expect(screen.queryByText('Setup guide complete')).not.toBeInTheDocument()
    expect(screen.queryByText('Setup progress: 3/3')).not.toBeInTheDocument()
    for (const name of ['API Keys', 'Channels', 'Usage Logs', 'Pricing']) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument()
    }
    const panel = document.getElementById(
      toggle.getAttribute('aria-controls') ?? ''
    )
    expect(panel).toBeInTheDocument()
    expect(panel).not.toBeVisible()
  })

  it('toggles the completed guide with the keyboard and restores focus after hiding it', async () => {
    const user = userEvent.setup()
    await renderOverview()
    const toggle = await screen.findByRole('button', { name: 'Setup guide' })

    await user.tab()
    expect(toggle).toHaveFocus()
    await user.keyboard('{Enter}')
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(
      document.getElementById(toggle.getAttribute('aria-controls') ?? '')
    ).toBeVisible()
    expect(
      screen.getByRole('heading', {
        name: 'Build on your API gateway in minutes',
      })
    ).toBeVisible()
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^API Keys/ })).toBeVisible()
    )

    await user.keyboard(' ')
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
    await user.click(toggle)
    await user.click(screen.getByRole('button', { name: 'Hide setup guide' }))
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(toggle).toHaveFocus()
  })

  it('restores the completed guide preference after remounting', async () => {
    const user = userEvent.setup()
    const first = await renderOverview()
    await user.click(await screen.findByRole('button', { name: 'Setup guide' }))
    first.unmount()

    const second = await renderOverview()
    expect(
      await screen.findByRole('button', { name: 'Setup guide' })
    ).toHaveAttribute('aria-expanded', 'true')
    await user.click(screen.getByRole('button', { name: 'Hide setup guide' }))
    second.unmount()

    await renderOverview()
    expect(
      await screen.findByRole('button', { name: 'Setup guide' })
    ).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('Setup guide complete')).not.toBeInTheDocument()
  })

  it('keeps the existing progress banner when an incomplete guide is manually collapsed', async () => {
    const user = userEvent.setup()
    useAuthStore
      .getState()
      .auth.setUser({ id: 1, username: 'new-user', role: 1 })
    await renderOverview()

    await user.click(
      await screen.findByRole('button', { name: 'Hide setup guide' })
    )
    expect(screen.getByText('Setup progress: 1/3')).toBeVisible()
    expect(
      screen.getByText('Setup guide is collapsed. Expand it anytime.')
    ).toBeVisible()
    expect(screen.getByRole('button', { name: 'API Keys' })).toBeVisible()
    expect(
      screen.queryByRole('button', { name: 'Setup guide' })
    ).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show setup guide' }))
    expect(
      screen.getByRole('button', { name: 'Hide setup guide' })
    ).toBeVisible()
  })

  it('removes the collapsed progress banner when the remaining setup step completes', async () => {
    useAuthStore.getState().auth.setUser({
      id: 1,
      username: 'dashboard-user',
      role: 1,
      quota: 1000000,
    })
    window.localStorage.setItem(storageKey, 'collapsed')
    await renderOverview()
    expect(await screen.findByText('Setup progress: 2/3')).toBeVisible()

    act(() => {
      useAuthStore.getState().auth.setUser({
        id: 1,
        username: 'dashboard-user',
        role: 1,
        quota: 1000000,
        request_count: 1,
      })
    })
    expect(
      await screen.findByRole('button', { name: 'Setup guide' })
    ).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText(/Setup progress:/)).not.toBeInTheDocument()
  })

  it('does not show a completed setup entry when the key lookup fails', async () => {
    keyLookupError = new Error('Key lookup unavailable')
    await renderOverview()

    expect(
      await screen.findByRole('button', { name: 'Hide setup guide' })
    ).toBeVisible()
    expect(
      screen.queryByRole('button', { name: 'Setup guide' })
    ).not.toBeInTheDocument()
  })
})

const orgA = 'org:11111111-1111-4111-8111-111111111111'
const orgB = 'org:22222222-2222-4222-8222-222222222222'
const subject = '33333333-3333-4333-8333-333333333333'
function account(workspaceKey: string): ManagedAccountContext {
  return {
    workspace_key: workspaceKey,
    account_label: workspaceKey === orgA ? 'Team A' : 'Team B',
    account_kind: 'org',
    native_owner_id: workspaceKey === orgA ? 10 : 20,
    resource_scope: { kind: 'subject', subject_ref: subject },
    allowed_actions: [
      'model.keys.read',
      'model.keys.reveal',
      'model.keys.create',
      'model.usage.read',
    ],
    allowed_update_fields: ['name'],
    allowed_statuses: [2],
  }
}

it('uses scoped usage and an external key for an organization overview without personal wallet or Playground guidance', async () => {
  const user = userEvent.setup()
  useAuthStore.getState().auth.setUser({
    id: 1,
    username: 'member',
    role: 1,
    quota: 999999999,
    used_quota: 888888888,
    request_count: 123456,
    permissions: { model_service_only: true },
  })
  const fallback = vi.mocked(api.get).getMockImplementation()
  if (!fallback) throw new Error('Missing API fixture')
  vi.mocked(api.get).mockImplementation(async (url, config) => {
    if (url === '/api/status') return fallback(url, config)
    expect(config?.headers).toMatchObject({ 'X-SAI-Workspace-Key': orgA })
    if (url === '/api/token/context') {
      return { data: { success: true, data: account(orgA) } }
    }
    if (url.startsWith('/api/token/?')) {
      return {
        data: {
          success: true,
          data: {
            items: [
              {
                id: 99,
                name: 'Automatic Pilot',
                managed: true,
                key: '',
                status: 1,
              },
              { id: 11, name: 'Member device', key: 'masked', status: 1 },
            ],
          },
        },
      }
    }
    if (url === '/api/user/models') {
      return { data: { success: true, data: ['scope-model'] } }
    }
    if (url === '/api/data/self') {
      return {
        data: {
          success: true,
          data: [
            {
              model_name: 'scope-model',
              created_at: Math.floor(Date.now() / 1000),
              quota: 500000,
              count: 3,
              token_used: 4321,
            },
          ],
        },
      }
    }
    throw new Error(`Unexpected scoped URL ${url}`)
  })
  const post = vi.spyOn(api, 'post').mockResolvedValue({
    data: { success: true, data: { key: 'synthetic-external-key' } },
  })
  await renderOverview(orgA)
  await screen.findByRole('heading', { name: 'Team A · Overview' })
  await screen.findByText('4,321')
  expect(screen.queryByText('Historical Usage')).not.toBeInTheDocument()
  expect(screen.queryByText('Credit remaining')).not.toBeInTheDocument()
  expect(screen.queryByText('123,456')).not.toBeInTheDocument()
  await user.click(await screen.findByRole('button', { name: 'Setup guide' }))
  expect(
    screen.queryByRole('link', { name: /Add credits|Send a request|Wallet/ })
  ).not.toBeInTheDocument()
  expect(screen.getByText('Member device')).toBeVisible()
  expect(screen.queryByText('Automatic Pilot')).not.toBeInTheDocument()
  await user.click(
    screen.getByRole('button', { name: 'Copy ready-to-run curl' })
  )
  await waitFor(() =>
    expect(post).toHaveBeenCalledWith(
      '/api/token/11/key',
      undefined,
      expect.objectContaining({
        headers: { 'X-SAI-Workspace-Key': orgA },
        signal: expect.any(AbortSignal),
      })
    )
  )
  expect(
    vi
      .mocked(api.get)
      .mock.calls.filter(([url]) => url === '/api/token/context')
  ).toHaveLength(1)
})

it('late usage from another organization cannot replace the newly selected account', async () => {
  let finishA!: (value: unknown) => void
  const lateA = new Promise((resolve) => {
    finishA = resolve
  })
  const fallback = vi.mocked(api.get).getMockImplementation()
  if (!fallback) throw new Error('Missing API fixture')
  vi.mocked(api.get).mockImplementation(async (url, config) => {
    const key = String(config?.headers?.['X-SAI-Workspace-Key'] ?? '')
    if (url === '/api/status') return fallback(url, config)
    if (url === '/api/token/context') {
      return { data: { success: true, data: account(key) } }
    }
    if (url === '/api/user/models') {
      return { data: { success: true, data: ['scope-model'] } }
    }
    if (url.startsWith('/api/token/?')) {
      return { data: { success: true, data: { items: [] } } }
    }
    if (url === '/api/data/self') {
      if (key === orgA) return lateA
      return {
        data: {
          success: true,
          data: [{ created_at: 1, quota: 0, count: 7, token_used: 7654 }],
        },
      }
    }
    throw new Error(`Unexpected scoped URL ${url}`)
  })
  const view = await renderOverview(orgA)
  await screen.findByRole('heading', { name: 'Team A · Overview' })
  await act(() =>
    view.router.navigate({ to: '/', search: { workspace_key: orgB } })
  )
  await screen.findByText('7,654')
  await act(async () =>
    finishA({
      data: {
        success: true,
        data: [{ created_at: 1, quota: 0, count: 99, token_used: 987654 }],
      },
    })
  )
  expect(
    screen.getByRole('heading', { name: 'Team B · Overview' })
  ).toBeVisible()
  expect(screen.queryByText('987,654')).not.toBeInTheDocument()
})

it('organization data requests always use the scoped self endpoints even for a Native administrator', async () => {
  vi.mocked(api.get).mockResolvedValue({ data: { success: true, data: [] } })
  const params = { start_timestamp: 1, end_timestamp: 2 }
  await getUserQuotaDates(params, true, orgA)
  await getFlowQuotaDates(params, true, orgA)
  expect(vi.mocked(api.get).mock.calls.map(([url]) => url)).toEqual([
    '/api/data/self',
    '/api/data/flow/self',
  ])
  for (const [, config] of vi.mocked(api.get).mock.calls) {
    expect(config?.headers).toMatchObject({ 'X-SAI-Workspace-Key': orgA })
  }
})

it('an overview containing only automatically managed keys never offers a secret request example', async () => {
  const fallback = vi.mocked(api.get).getMockImplementation()
  if (!fallback) throw new Error('Missing API fixture')
  vi.mocked(api.get).mockImplementation(async (url, config) => {
    if (url === '/api/token/context') {
      return { data: { success: true, data: account(orgA) } }
    }
    if (url.startsWith('/api/token/?')) {
      return {
        data: {
          success: true,
          data: {
            items: [
              {
                id: 99,
                name: 'Automatic Pilot',
                managed: true,
                key: '',
                status: 1,
              },
            ],
          },
        },
      }
    }
    return fallback(url, config)
  })
  const post = vi.spyOn(api, 'post')
  await renderOverview(orgA)
  await screen.findByRole('button', { name: 'Hide setup guide' })
  expect(
    screen.queryByRole('button', { name: 'Copy ready-to-run curl' })
  ).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})

it('a secret response from a closed organization preview cannot be copied after switching accounts', async () => {
  const user = userEvent.setup()
  const write = vi.spyOn(navigator.clipboard, 'writeText').mockResolvedValue()
  const fallback = vi.mocked(api.get).getMockImplementation()
  if (!fallback) throw new Error('Missing API fixture')
  vi.mocked(api.get).mockImplementation(async (url, config) => {
    const key = String(config?.headers?.['X-SAI-Workspace-Key'] ?? '')
    if (url === '/api/token/context') {
      return { data: { success: true, data: account(key) } }
    }
    return fallback(url, config)
  })
  let finish!: (value: unknown) => void
  const pending = new Promise((resolve) => {
    finish = resolve
  })
  const post = vi.spyOn(api, 'post').mockImplementation(() => pending)
  const view = await renderOverview(orgA)
  await user.click(await screen.findByRole('button', { name: 'Setup guide' }))
  await user.click(
    screen.getByRole('button', { name: 'Copy ready-to-run curl' })
  )
  await waitFor(() => expect(post).toHaveBeenCalled())
  await act(() =>
    view.router.navigate({ to: '/', search: { workspace_key: orgB } })
  )
  await screen.findByRole('heading', { name: 'Team B · Overview' })
  await act(async () =>
    finish({ data: { success: true, data: { key: 'synthetic-stale-key' } } })
  )
  expect(write).not.toHaveBeenCalled()
})

it.each([false, true])(
  'organization cache cards distinguish confirmed zero from unavailable totals (known=%s)',
  async (known) => {
    vi.mocked(api.get).mockResolvedValue({
      data: {
        success: true,
        data: [
          {
            created_at: 1,
            quota: 0,
            count: 3,
            token_used: 100,
            ...(known
              ? { cache_read_tokens: 0, cache_creation_tokens: 0 }
              : {}),
          },
        ],
      },
    })
    render(
      <QueryClientProvider client={client}>
        <LogStatCards workspaceKey={orgA} scopeKey='scope-a' />
      </QueryClientProvider>
    )
    await waitFor(() =>
      expect(
        screen.getByRole('group', { name: 'Total Count' })
      ).toHaveTextContent('3')
    )
    for (const name of ['Cache Read', 'Cache Write']) {
      if (known) {
        expect(screen.getByRole('group', { name })).toHaveTextContent('0')
      } else {
        expect(screen.queryByRole('group', { name })).not.toBeInTheDocument()
      }
    }
  }
)

it('does not reveal a key for a request example before an authorized model is available', async () => {
  const user = userEvent.setup()
  const fallback = vi.mocked(api.get).getMockImplementation()
  if (!fallback) throw new Error('Missing API fixture')
  vi.mocked(api.get).mockImplementation(async (url, config) => {
    if (url === '/api/token/context') {
      return { data: { success: true, data: account(orgA) } }
    }
    if (url === '/api/user/models') {
      return { data: { success: true, data: [] } }
    }
    return fallback(url, config)
  })
  const post = vi.spyOn(api, 'post')
  await renderOverview(orgA)
  await user.click(await screen.findByRole('button', { name: 'Setup guide' }))
  expect(screen.getByText('No available models')).toBeVisible()
  expect(
    screen.queryByRole('button', { name: 'Copy ready-to-run curl' })
  ).not.toBeInTheDocument()
  expect(post).not.toHaveBeenCalled()
})
