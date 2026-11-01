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
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react'
import { afterEach, describe, expect, test } from 'vitest'

import type { ApiKey } from '../../types'

const { createInstance } = await import('i18next')
const { I18nextProvider, initReactI18next } = await import('react-i18next')
const { QueryClient, QueryClientProvider } =
  await import('@tanstack/react-query')
const { api } = await import('@/lib/api')
const { ApiKeysProvider } = await import('../api-keys-provider')
const { ApiKeysMutateDrawer } = await import('../api-keys-mutate-drawer')
const { apiKeySchema } = await import('../../types')

const i18n = createInstance()
await i18n.use(initReactI18next).init({
  lng: 'en',
  resources: { en: { translation: {} } },
})

type ApiMethod = (
  url: string,
  data?: unknown,
  options?: { headers?: Record<string, string> }
) => Promise<{ data: unknown }>
type MockableApi = {
  get: ApiMethod
  post: ApiMethod
}
type RenderedDrawer = {
  queryClient: InstanceType<typeof QueryClient>
  view: ReturnType<typeof render>
}

const apiClient = api as unknown as MockableApi
const originalGet = apiClient.get
const originalPost = apiClient.post
let renderedDrawer: RenderedDrawer | null = null

function installApiFixtures(createdPayloads: Array<Record<string, unknown>>) {
  apiClient.get = async (url) => {
    switch (url) {
      case '/api/status':
        return { data: { data: { default_use_auto_group: true } } }
      case '/api/user/models':
        return { data: { success: true, data: [] } }
      case '/api/user/self/groups':
        return {
          data: {
            success: true,
            data: {
              auto: { desc: 'Automatic routing', ratio: 'auto' },
              default: { desc: 'Standard access', ratio: 1 },
              vip: { desc: 'Priority access', ratio: 2 },
            },
          },
        }
      case '/api/token/auto-groups':
        return {
          data: {
            success: true,
            data: { groups: ['vip', 'default'], max_count: 3 },
          },
        }
      default:
        throw new Error(`Unexpected GET ${url}`)
    }
  }
  apiClient.post = async (url, data) => {
    expect(url).toBe('/api/token/')
    expect(data && typeof data === 'object').toBeTruthy()
    createdPayloads.push(data as Record<string, unknown>)
    return { data: { success: true, data: {} } }
  }
}

async function renderCreateDrawer(recovery = false): Promise<void> {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const freshAt = Date.now() + 60_000
  queryClient.setQueryData(
    ['status'],
    { default_use_auto_group: true },
    { updatedAt: freshAt }
  )
  queryClient.setQueryData(
    ['user-models'],
    { success: true, data: [] },
    { updatedAt: freshAt }
  )
  queryClient.setQueryData(
    ['user-groups'],
    {
      success: true,
      data: {
        auto: { desc: 'Automatic routing', ratio: 'auto' },
        default: { desc: 'Standard access', ratio: 1 },
        vip: { desc: 'Priority access', ratio: 2 },
      },
    },
    { updatedAt: freshAt }
  )
  queryClient.setQueryData(
    ['token-auto-groups'],
    {
      success: true,
      data: { groups: ['vip', 'default'], max_count: 3 },
    },
    { updatedAt: freshAt }
  )
  const view = render(drawerContent(queryClient))
  renderedDrawer = { queryClient, view }
  await waitFor(
    () => {
      const saveButton = findButton(recovery ? 'Retry' : 'Save changes', false)
      expect(saveButton).toBeEnabled()
    },
    { timeout: 1500 }
  )
}

function drawerContent(
  queryClient: InstanceType<typeof QueryClient>,
  row?: ApiKey
) {
  return (
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <ApiKeysProvider>
          <ApiKeysMutateDrawer
            open
            onOpenChange={() => undefined}
            currentRow={row}
          />
        </ApiKeysProvider>
      </I18nextProvider>
    </QueryClientProvider>
  )
}

function findButton(text: string, required: true): HTMLButtonElement
function findButton(text: string, required: false): HTMLButtonElement | null
function findButton(text: string, required = true): HTMLButtonElement | null {
  const button = screen
    .queryAllByRole<HTMLButtonElement>('button')
    .find((candidate) => candidate.textContent?.includes(text))
  if (required && !button) {
    throw new Error(`Expected button containing "${text}"`)
  }
  return button ?? null
}

function getControlByLabel(labelText: 'Name' | 'Quantity'): HTMLInputElement
function getControlByLabel(labelText: 'Group'): HTMLButtonElement
function getControlByLabel(labelText: 'Auto group order'): HTMLElement
function getControlByLabel(labelText: string): HTMLElement {
  const label = [...document.querySelectorAll<HTMLLabelElement>('label')].find(
    (candidate) => candidate.textContent?.trim() === labelText
  )
  if (!label) {
    throw new Error(`Expected label "${labelText}"`)
  }

  const control =
    label.control ??
    label
      .closest('[data-slot="form-item"]')
      ?.querySelector<HTMLElement>(
        '[data-slot="form-control"], input, textarea, button[role="combobox"], [role="group"]'
      )
  if (!control) {
    throw new Error(`Expected control for label "${labelText}"`)
  }
  return control
}

function changeInput(input: HTMLInputElement, value: string): void {
  fireEvent.input(input, { target: { value } })
}

function selectComboboxOption(
  trigger: HTMLButtonElement,
  optionDescription: string
): void {
  fireEvent.click(trigger)
  const option = [
    ...document.querySelectorAll<HTMLElement>('[data-slot="command-item"]'),
  ].find((candidate) => candidate.textContent?.includes(optionDescription))
  if (!option) {
    throw new Error(`Expected option containing "${optionDescription}"`)
  }
  fireEvent.click(option)
}

afterEach(() => {
  apiClient.get = originalGet
  apiClient.post = originalPost
  localStorage.clear()
  sessionStorage.clear()
  if (renderedDrawer) {
    renderedDrawer.queryClient.clear()
    renderedDrawer = null
  }
})

describe('API keys mutate drawer Auto group integration', () => {
  test('a pending create does not block editing another key and is restored on return', async () => {
    installApiFixtures([])
    const originalFixtureGet = apiClient.get
    const row = apiKeySchema.parse({
      id: 41,
      name: 'existing-key',
      key: '',
      status: 1,
      remain_quota: 0,
      used_quota: 0,
      unlimited_quota: true,
      expired_time: -1,
      created_time: 1,
      accessed_time: 1,
      model_limits_enabled: false,
      group: 'default',
    })
    apiClient.get = async (url, ...args) =>
      url === '/api/token/41'
        ? { data: { success: true, data: row } }
        : originalFixtureGet(url, ...args)
    apiClient.post = async () => {
      throw Object.assign(new Error('unknown'), {
        isAxiosError: true,
        response: { status: 503 },
      })
    }
    await renderCreateDrawer()
    changeInput(getControlByLabel('Name'), 'pending-create')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Retry$/ })).toBeEnabled()
    )
    const drawer = renderedDrawer
    if (!drawer) throw new Error('Drawer did not mount')
    drawer.view.rerender(drawerContent(drawer.queryClient, row))
    await waitFor(() => expect(findButton('Save changes', true)).toBeEnabled())
    expect(getControlByLabel('Name')).toHaveValue('existing-key')
    drawer.view.rerender(drawerContent(drawer.queryClient))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Retry$/ })).toBeEnabled()
    )
    expect(getControlByLabel('Name')).toHaveValue('pending-create')
  })

  test('a retired creation receipt allows a new operation instead of replaying it forever', async () => {
    installApiFixtures([])
    const requests: string[] = []
    apiClient.post = async (_url, _payload, options) => {
      const id = options?.headers?.['Idempotency-Key']
      if (!id) throw new Error('Creation request lacks operation identity')
      requests.push(id)
      if (requests.length <= 2) {
        throw Object.assign(new Error('retired or unknown'), {
          isAxiosError: true,
          response: { status: requests.length === 1 ? 503 : 410 },
        })
      }
      return { data: { success: true, data: { id: 42 } } }
    }
    await renderCreateDrawer()
    changeInput(getControlByLabel('Name'), 'original-request')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Retry$/ })).toBeEnabled()
    )
    fireEvent.click(findButton('Retry', true))
    await waitFor(() => expect(findButton('Save changes', true)).toBeEnabled())
    expect(
      sessionStorage.getItem('newapi:pending-key-creation:personal')
    ).toBeNull()
    changeInput(getControlByLabel('Name'), 'new-request')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() => expect(requests).toHaveLength(3))
    expect(requests[1]).toBe(requests[0])
    expect(requests[2]).not.toBe(requests[0])
  })

  test('restores the original create request after an unknown response and drawer remount', async () => {
    installApiFixtures([])
    const requests: Array<{ id: string; payload: unknown }> = []
    apiClient.post = async (_url, payload, options) => {
      const id = options?.headers?.['Idempotency-Key']
      if (!id) throw new Error('Creation request lacks operation identity')
      requests.push({ id, payload })
      if (requests.length === 1) {
        throw Object.assign(new Error('response lost'), {
          isAxiosError: true,
          response: { status: 503 },
        })
      }
      return { data: { success: true, data: { id: 41 } } }
    }
    await renderCreateDrawer()
    changeInput(getControlByLabel('Name'), 'retained-request')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() =>
      expect(screen.getByRole('button', { name: /^Retry$/ })).toBeTruthy()
    )
    cleanup()
    await renderCreateDrawer(true)
    expect(getControlByLabel('Name').value).toBe('retained-request')
    fireEvent.click(findButton('Retry', true))
    await waitFor(() => expect(requests).toHaveLength(2))
    expect(requests[1]).toEqual(requests[0])
    await waitFor(() =>
      expect(
        sessionStorage.getItem('newapi:pending-key-creation:personal')
      ).toBeNull()
    )
  })

  test('inherits the root Auto order and sends an empty override for every batch-created key', async () => {
    const createdPayloads: Array<Record<string, unknown>> = []
    installApiFixtures(createdPayloads)
    await renderCreateDrawer()

    const groupTrigger = getControlByLabel('Group')
    expect(groupTrigger.textContent?.includes('auto')).toBe(true)
    expect(
      document.body.textContent?.includes(
        'Using the complete global Auto order (2 groups)'
      )
    ).toBe(true)
    expect(
      [
        ...document.querySelectorAll('[data-slot="global-auto-order-name"]'),
      ].map((item) => item.textContent)
    ).toEqual(['vip', 'default'])
    expect(findButton('Restore global Auto', true).disabled).toBe(true)

    changeInput(getControlByLabel('Name'), 'batch')
    changeInput(getControlByLabel('Quantity'), '2')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() => expect(createdPayloads).toHaveLength(2))

    expect(createdPayloads.length).toBe(2)
    expect(createdPayloads[0]?.name).toBe('batch')
    for (const payload of createdPayloads) {
      expect(payload.group).toBe('auto')
      expect(payload.auto_groups).toEqual([])
      expect(payload.cross_group_retry).toBe(true)
    }
  })

  test('preserves an unsaved custom order and mode after Auto to ordinary to Auto changes', async () => {
    const createdPayloads: Array<Record<string, unknown>> = []
    installApiFixtures(createdPayloads)
    await renderCreateDrawer()

    const autoOrderControl = getControlByLabel('Auto group order')
    const addGroupTrigger = autoOrderControl.querySelector<HTMLButtonElement>(
      'button[role="combobox"]'
    )
    if (!addGroupTrigger) {
      throw new Error('Expected Auto group order combobox')
    }
    selectComboboxOption(addGroupTrigger, 'Priority access')

    expect(
      document.querySelector('button[aria-label="Remove vip"]')
    ).toBeTruthy()
    expect(document.body.textContent?.includes('1 / 3 groups selected')).toBe(
      true
    )
    expect(findButton('Restore global Auto', true).disabled).toBe(false)

    const groupTrigger = getControlByLabel('Group')
    selectComboboxOption(groupTrigger, 'Standard access')
    expect(document.querySelector('button[aria-label="Remove vip"]')).toBe(null)
    selectComboboxOption(groupTrigger, 'Automatic routing')

    expect(
      document.querySelector('button[aria-label="Remove vip"]')
    ).toBeTruthy()
    expect(document.body.textContent?.includes('1 / 3 groups selected')).toBe(
      true
    )
    expect(findButton('Restore global Auto', true).disabled).toBe(false)

    changeInput(getControlByLabel('Name'), 'custom')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() => expect(createdPayloads).toHaveLength(1))
    expect(createdPayloads[0]?.auto_groups).toEqual(['vip'])
  })
})

describe('API keys mutate drawer user quota query switch', () => {
  test('sends false for a new key after the switch, which starts on, is turned off', async () => {
    const createdPayloads: Array<Record<string, unknown>> = []
    installApiFixtures(createdPayloads)
    await renderCreateDrawer()

    fireEvent.click(findButton('Advanced Settings', true))
    const quotaQuerySwitch = await screen.findByRole('switch', {
      name: 'Allow querying user quota',
    })
    expect(quotaQuerySwitch).toBeChecked()
    fireEvent.click(quotaQuerySwitch)
    expect(quotaQuerySwitch).not.toBeChecked()

    changeInput(getControlByLabel('Name'), 'no-user-quota')
    fireEvent.click(findButton('Save changes', true))
    await waitFor(() => expect(createdPayloads).toHaveLength(1))
    expect(createdPayloads[0]?.allow_user_quota_query).toBe(false)
  })
})
