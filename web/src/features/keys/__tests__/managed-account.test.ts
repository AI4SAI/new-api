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
import {
  createRootRoute,
  createRoute,
  createRouter,
  createMemoryHistory,
} from '@tanstack/react-router'
import { beforeEach, describe, expect, test, vi } from 'vitest'

import { getPricing } from '@/features/pricing/api'
import { buildApiParams } from '@/features/usage-logs/lib/utils'
import {
  modelWorkspaceSearch,
  modelWorkspaceSearchSchema,
} from '@/lib/model-workspace'

import {
  getApiKeys,
  getManagedAccountContext,
  updateApiKeyStatus,
  fetchTokenKey,
} from '../api'
import {
  API_KEY_FORM_DEFAULT_VALUES,
  transformFormDataToPayload,
} from '../lib/api-key-form'

const http = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('@/lib/api', () => ({ api: http }))

beforeEach(() => {
  for (const method of Object.values(http)) {
    method.mockReset().mockResolvedValue({
      data: { success: true, data: { items: [], key: 'test-key' } },
    })
  }
})

describe('managed model account requests', () => {
  test('renamed keys read their original log history by immutable ID', () => {
    const params = buildApiParams({
      page: 1,
      pageSize: 20,
      isAdmin: false,
      searchParams: { token_id: 13, token: 'Renamed key' },
      columnFilters: [{ id: 'token_name', value: 'Renamed key' }],
    })
    expect(params.token_id).toBe(13)
    expect(params).not.toHaveProperty('token_name')
  })
  test('organization A, B and personal requests keep separate explicit headers', async () => {
    const a = 'org:11111111-1111-4111-8111-111111111111'
    const b = 'org:22222222-2222-4222-8222-222222222222'
    await Promise.all([getApiKeys({}, a), getApiKeys({}, b), getApiKeys()])
    expect(http.get.mock.calls.map((call) => call[1].headers)).toEqual([
      { 'X-SAI-Workspace-Key': a },
      { 'X-SAI-Workspace-Key': b },
      undefined,
    ])
    expect(
      http.get.mock.calls.slice(0, 2).every((call) => call[1].disableDuplicate)
    ).toBe(true)
    await updateApiKeyStatus(13, 2, b)
    await fetchTokenKey(13, a)
    expect(http.put.mock.calls[0][2].headers).toEqual({
      'X-SAI-Workspace-Key': b,
    })
    expect(http.post.mock.calls[0][2].headers).toEqual({
      'X-SAI-Workspace-Key': a,
    })
  })

  test('a mismatched context cannot initialize a different account', async () => {
    http.get.mockResolvedValue({
      data: {
        success: true,
        data: {
          workspace_key: 'org:other',
          native_owner_id: 2,
          account_label: 'Other',
          account_kind: 'org',
        },
      },
    })
    await expect(getManagedAccountContext('org:requested')).rejects.toThrow(
      'Invalid model account context'
    )
  })

  test('denied or unavailable management never retries as personal', async () => {
    for (const status of [401, 403, 503]) {
      http.get.mockRejectedValueOnce({ response: { status } })
      await expect(
        getManagedAccountContext('org:requested')
      ).rejects.toMatchObject({ response: { status } })
    }
    expect(http.get).toHaveBeenCalledTimes(3)
    expect(
      http.get.mock.calls.every(
        (call) => call[1].headers['X-SAI-Workspace-Key'] === 'org:requested'
      )
    ).toBe(true)
  })

  test('editing metadata does not replace the consumed quota snapshot', () => {
    const unchanged = transformFormDataToPayload(
      {
        ...API_KEY_FORM_DEFAULT_VALUES,
        name: 'Renamed',
        remain_quota_dollars: 0,
      },
      true
    )
    expect(unchanged).not.toHaveProperty('remain_quota')
    expect(unchanged).not.toHaveProperty('quota_delta')
    const changed = transformFormDataToPayload(
      { ...API_KEY_FORM_DEFAULT_VALUES, remain_quota_dollars: -1 },
      true
    )
    expect(changed).not.toHaveProperty('remain_quota')
    expect(changed.quota_delta).toBeLessThan(0)
  })
})

test('organization context survives model navigation and can explicitly return to personal', async () => {
  const workspace = 'org:11111111-1111-4111-8111-111111111111'
  const root = createRootRoute({
    validateSearch: modelWorkspaceSearchSchema,
    search: modelWorkspaceSearch,
  })
  const routes = [
    '/',
    '/docs',
    '/sign-in',
    '/oauth/oidc',
    '/keys',
    '/pricing',
    '/pricing/$modelId',
    '/usage-logs/common',
  ].map((path) =>
    createRoute({
      getParentRoute: () => root,
      path,
    })
  )
  const router = createRouter({
    routeTree: root.addChildren(routes),
    history: createMemoryHistory({
      initialEntries: [`/keys?workspace_key=${encodeURIComponent(workspace)}`],
    }),
  })
  await router.load()
  for (const path of [
    '/',
    '/docs',
    '/sign-in',
    '/oauth/oidc',
    '/pricing',
    '/pricing/synthetic-model',
    '/keys',
    '/usage-logs/common',
  ]) {
    await router.navigate({ href: path })
    expect(router.state.location.search).toEqual({ workspace_key: workspace })
  }
  await router.navigate({ to: '/keys', search: { workspace_key: undefined } })
  expect(router.state.location.search.workspace_key).toBeUndefined()
})

test('pricing carries the same explicit organization context as key management', async () => {
  const a = 'org:11111111-1111-4111-8111-111111111111'
  const b = 'org:22222222-2222-4222-8222-222222222222'
  await Promise.all([getPricing(a), getPricing(b), getPricing()])
  expect(http.get.mock.calls.map((call) => call[1].headers)).toEqual([
    { 'X-SAI-Workspace-Key': a },
    { 'X-SAI-Workspace-Key': b },
    undefined,
  ])
  expect(http.get.mock.calls.map((call) => call[1].disableDuplicate)).toEqual([
    true,
    true,
    false,
  ])
})
