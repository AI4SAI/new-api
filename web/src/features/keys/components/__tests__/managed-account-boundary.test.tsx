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
import { act, render, screen } from '@testing-library/react'
import axios from 'axios'
import { afterEach, expect, test, vi } from 'vitest'

import { getManagedAccountContext } from '../../api'
import type { ManagedAccountContext } from '../../types'
import { ManagedAccountBoundary } from '../managed-account-boundary'

vi.mock('../../api', () => ({ getManagedAccountContext: vi.fn() }))

let client: QueryClient
afterEach(() => {
  client?.clear()
  vi.resetAllMocks()
})

function content(workspaceKey?: string) {
  return (
    <QueryClientProvider client={client}>
      <ManagedAccountBoundary workspaceKey={workspaceKey}>
        {(account) => <p>{account?.account_label || 'Personal keys'}</p>}
      </ManagedAccountBoundary>
    </QueryClientProvider>
  )
}

test('a late organization response cannot replace another organization or personal view', async () => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  let finishA: (value: ManagedAccountContext) => void = () => undefined
  const a = new Promise<ManagedAccountContext>((resolve) => {
    finishA = resolve
  })
  vi.mocked(getManagedAccountContext).mockImplementation(async (key) =>
    key === 'org:a'
      ? a
      : {
          workspace_key: key,
          native_owner_id: 22,
          account_label: 'Organization B',
          account_kind: 'org',
        }
  )
  const view = render(content('org:a'))
  expect(screen.queryByText('Personal keys')).not.toBeInTheDocument()
  view.rerender(content('org:b'))
  await screen.findByText('Organization B')
  await act(async () => {
    finishA({
      workspace_key: 'org:a',
      native_owner_id: 11,
      account_label: 'Organization A',
      account_kind: 'org',
    })
  })
  expect(screen.queryByText('Organization A')).not.toBeInTheDocument()
  expect(screen.getByText('Organization B')).toBeVisible()
  view.rerender(content())
  expect(screen.getByText('Personal keys')).toBeVisible()
  expect(screen.queryByText('Organization B')).not.toBeInTheDocument()
})

test.each([403, 503])(
  'management error %s never falls back to personal keys',
  async (status) => {
    client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    vi.mocked(getManagedAccountContext).mockRejectedValue(
      new axios.AxiosError('denied', undefined, undefined, undefined, {
        status,
        statusText: 'denied',
        data: {},
        headers: {},
        config: { headers: new axios.AxiosHeaders() },
      })
    )
    render(content('org:a'))
    await screen.findByText(
      status === 403 ? 'Access denied' : 'Model account unavailable'
    )
    expect(screen.queryByText('Personal keys')).not.toBeInTheDocument()
    expect(getManagedAccountContext).toHaveBeenCalledTimes(1)
  }
)
