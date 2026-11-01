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
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import { createInstance } from 'i18next'
import { I18nextProvider, initReactI18next } from 'react-i18next'
import { afterEach, expect, test, vi } from 'vitest'

import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/auth-store'

import { DEFAULT_CONFIG } from '../constants'
import { Playground } from '../index'
import { saveConfig } from '../lib/storage/storage'

const i18n = createInstance()
await i18n
  .use(initReactI18next)
  .init({ lng: 'en', resources: { en: { translation: {} } } })
afterEach(() => {
  cleanup()
  localStorage.clear()
  useAuthStore.getState().auth.reset()
  vi.restoreAllMocks()
})

test.each([true, false])(
  'first entry prepares before sending and recovers when initial ready is %s',
  async (initialReady) => {
    useAuthStore
      .getState()
      .auth.setUser({ id: 7, username: 'playground-user', role: 1 })
    saveConfig({ ...DEFAULT_CONFIG, stream: false })
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    })
    vi.spyOn(api, 'get').mockImplementation(async (url) => {
      if (url === '/api/user/models') {
        return { data: { success: true, data: ['gpt-4o'] } }
      }
      if (url === '/api/user/self/groups') {
        return {
          data: {
            success: true,
            data: { default: { desc: 'Default', ratio: 1 } },
          },
        }
      }
      throw new Error(`Unexpected GET ${url}`)
    })
    let complete!: (value: {
      data: { success: boolean; data: { ready: boolean } }
    }) => void
    const initial = new Promise<{
      data: { success: boolean; data: { ready: boolean } }
    }>((resolve) => {
      complete = resolve
    })
    const post = vi
      .spyOn(api, 'post')
      .mockImplementationOnce(() => initial)
      .mockImplementation(async (url) => {
        if (url === '/api/user/self/playground') {
          return { data: { success: true, data: { ready: true } } }
        }
        if (url === '/pg/chat/completions') {
          return {
            data: {
              choices: [
                {
                  message: { role: 'assistant', content: 'Prepared answer' },
                  finish_reason: 'stop',
                },
              ],
            },
          }
        }
        throw new Error(`Unexpected POST ${url}`)
      })
    const view = render(
      <QueryClientProvider client={queryClient}>
        <I18nextProvider i18n={i18n}>
          <Playground />
        </I18nextProvider>
      </QueryClientProvider>
    )
    expect(screen.getByPlaceholderText('Ask anything')).toBeDisabled()
    await act(async () => {
      complete({ data: { success: true, data: { ready: initialReady } } })
    })
    if (!initialReady) {
      fireEvent.click(await screen.findByRole('button', { name: 'Retry' }))
    }
    await waitFor(() =>
      expect(screen.getByPlaceholderText('Ask anything')).toBeEnabled()
    )
    fireEvent.change(screen.getByPlaceholderText('Ask anything'), {
      target: { value: 'Ready' },
    })
    const [send] = screen.getAllByRole('button', { name: /^Send/ })
    if (!send) throw new Error('Send control is missing')
    fireEvent.click(send)
    expect(await screen.findByText('Prepared answer')).toBeVisible()
    const preparationCalls = post.mock.calls.filter(
      ([url]) => url === '/api/user/self/playground'
    )
    expect(preparationCalls).toHaveLength(initialReady ? 1 : 2)
    expect(
      preparationCalls.every(([, body]) => JSON.stringify(body) === '{}')
    ).toBe(true)
    expect(
      post.mock.calls.filter(([url]) => url === '/pg/chat/completions')
    ).toHaveLength(1)
    view.unmount()
    queryClient.clear()
  }
)
