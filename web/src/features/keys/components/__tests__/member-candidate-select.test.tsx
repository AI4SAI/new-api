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
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'

import type { MemberCandidate } from '../../types'
import { MemberCandidateSelect } from '../member-candidate-select'

const workspace = 'org:11111111-1111-4111-8111-111111111111'
const alice = {
  subject_ref: '22222222-2222-4222-8222-222222222222',
  display_name: 'Alice',
  username: 'alice',
}
const bob = {
  subject_ref: '33333333-3333-4333-8333-333333333333',
  display_name: 'Bob',
  username: 'bob',
}
let client: QueryClient

function Selector() {
  const [member, setMember] = useState<MemberCandidate | null>(null)
  return (
    <MemberCandidateSelect
      workspaceKey={workspace}
      scopeKey='session-admin'
      value={member}
      onChange={setMember}
      allowClear
    />
  )
}

function renderSelector() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={client}>
      <Selector />
    </QueryClientProvider>
  )
}

afterEach(() => {
  cleanup()
  client?.clear()
  vi.restoreAllMocks()
})

test('member lookup failure keeps selection empty and Retry loads the directory', async () => {
  const get = vi
    .spyOn(api, 'get')
    .mockRejectedValueOnce(new Error('Unavailable'))
    .mockResolvedValue({
      data: { success: true, data: { items: [alice], next_cursor: '' } },
    })
  renderSelector()
  await userEvent.click(screen.getByRole('button', { name: 'Select a member' }))
  await userEvent.click(await screen.findByRole('button', { name: /Retry/ }))
  await screen.findByRole('option', { name: /Alice/ })
  expect(screen.getByRole('combobox', { name: 'Member' })).toHaveValue('')
  expect(get).toHaveBeenCalledTimes(2)
  expect(get.mock.calls[0][1]).toMatchObject({
    headers: { 'X-SAI-Workspace-Key': workspace },
    disableDuplicate: true,
  })
})

test('paged member choices keep earlier results and support selecting and clearing a member', async () => {
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
    const nextPage = new URL(url, 'https://example.test').searchParams.get(
      'after'
    )
    return {
      data: {
        success: true,
        data: {
          items: nextPage ? [bob] : [alice],
          next_cursor: nextPage ? '' : alice.subject_ref,
        },
      },
    }
  })
  renderSelector()
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Select a member' }))
  await user.click(await screen.findByRole('button', { name: 'Load more' }))
  await screen.findByRole('option', { name: /Bob/ })
  expect(screen.getByRole('option', { name: /Alice/ })).toBeVisible()
  expect(String(get.mock.calls[1][0])).toContain(`after=${alice.subject_ref}`)
  await user.click(screen.getByRole('option', { name: /Bob/ }))
  expect(screen.getByRole('combobox', { name: 'Member' })).toHaveValue('Bob')
  const clear = screen.getByRole('button', { name: /Clear/ })
  await user.click(clear)
  expect(screen.getByRole('combobox', { name: 'Member' })).toHaveValue('')
})

test('server search replaces unfiltered results and an empty directory remains selectable by a later search', async () => {
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => {
    const query = new URL(url, 'https://example.test').searchParams.get('query')
    return {
      data: {
        success: true,
        data: { items: query === 'ali' ? [alice] : [], next_cursor: '' },
      },
    }
  })
  renderSelector()
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Select a member' }))
  await screen.findByText('No results found')
  await user.type(screen.getByRole('combobox', { name: 'Member' }), 'ali')
  await screen.findByRole('option', { name: /Alice/ })
  await waitFor(() =>
    expect(
      get.mock.calls.some(([url]) => String(url).includes('query=ali'))
    ).toBe(true)
  )
  await user.keyboard('{ArrowDown}{Enter}')
  expect(screen.getByRole('combobox', { name: 'Member' })).toHaveValue('Alice')
})

test('an empty page with a scan cursor offers the next page without declaring no matches', async () => {
  const cursor = '44444444-4444-4444-8444-444444444444'
  const get = vi.spyOn(api, 'get').mockImplementation(async (url) => ({
    data: {
      success: true,
      data: new URL(url, 'https://example.test').searchParams.get('after')
        ? { items: [alice], next_cursor: '' }
        : { items: [], next_cursor: cursor },
    },
  }))
  renderSelector()
  const user = userEvent.setup()
  await user.click(screen.getByRole('button', { name: 'Select a member' }))
  const more = await screen.findByRole('button', { name: 'Load more' })
  await user.click(screen.getByRole('combobox', { name: 'Member' }))
  await user.keyboard('{ArrowDown}')
  expect(screen.queryByText(/No results found/)).not.toBeInTheDocument()
  await user.click(more)
  await screen.findByRole('option', { name: /Alice/ })
  expect(String(get.mock.calls[1][0])).toContain(`after=${cursor}`)
  await user.click(screen.getByRole('option', { name: /Alice/ }))
  expect(screen.getByRole('combobox', { name: 'Member' })).toHaveValue('Alice')
})
