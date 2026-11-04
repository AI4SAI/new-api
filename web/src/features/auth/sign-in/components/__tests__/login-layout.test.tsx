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
} from '@tanstack/react-router'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, test, vi } from 'vitest'

import type { SystemStatus } from '@/features/auth/types'
import { api } from '@/lib/api'
import { STATUS_QUERY_KEY } from '@/lib/status-query'

import { UserAuthForm } from '../user-auth-form'

afterEach(() => {
  vi.restoreAllMocks()
  localStorage.clear()
  sessionStorage.clear()
})

async function renderLogin(status: SystemStatus) {
  vi.spyOn(api, 'get').mockResolvedValue({
    data: { success: true, data: status },
  })
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  client.setQueryData(STATUS_QUERY_KEY, status)
  const root = createRootRoute({ component: UserAuthForm })
  const router = createRouter({
    routeTree: root,
    history: createMemoryHistory({ initialEntries: ['/'] }),
  })
  await router.load()
  render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}

test('password fields and submit precede OIDC in document and keyboard order', async () => {
  await renderLogin({
    password_login_enabled: true,
    oidc_enabled: true,
    oidc_display_name: 'Example SSO',
  })
  const oidc = await screen.findByRole('button', {
    name: 'Continue with Example SSO',
  })
  const username = screen.getByLabelText('Username or Email')
  const password = screen.getByLabelText('Password', { selector: 'input' })
  const submit = screen.getByRole('button', { name: 'Sign in' })
  expect(
    username.compareDocumentPosition(password) &
      Node.DOCUMENT_POSITION_FOLLOWING
  ).toBeTruthy()
  expect(
    password.compareDocumentPosition(submit) & Node.DOCUMENT_POSITION_FOLLOWING
  ).toBeTruthy()
  expect(
    submit.compareDocumentPosition(oidc) & Node.DOCUMENT_POSITION_FOLLOWING
  ).toBeTruthy()
  expect(screen.getAllByText('Or continue with')).toHaveLength(1)
  const user = userEvent.setup()
  await user.click(username)
  await user.tab()
  expect(password).toHaveFocus()
})

test('OIDC alone has no password fields or orphaned divider', async () => {
  await renderLogin({ password_login_enabled: false, oidc_enabled: true })
  expect(
    await screen.findByRole('button', { name: 'Continue with OIDC' })
  ).toBeVisible()
  expect(screen.queryByLabelText('Username or Email')).not.toBeInTheDocument()
  expect(
    screen.queryByLabelText('Password', { selector: 'input' })
  ).not.toBeInTheDocument()
  expect(screen.queryByText('Or continue with')).not.toBeInTheDocument()
})

test('password alone has no third-party divider', async () => {
  await renderLogin({ password_login_enabled: true })
  expect(await screen.findByRole('button', { name: 'Sign in' })).toBeVisible()
  expect(screen.queryByText('Or continue with')).not.toBeInTheDocument()
})

test('passkey and OIDC retain a divider when password login is disabled', async () => {
  await renderLogin({
    password_login_enabled: false,
    passkey_login: true,
    oidc_enabled: true,
  })
  const oidc = await screen.findByRole('button', { name: 'Continue with OIDC' })
  const passkey = screen.getByRole('button', { name: 'Sign in with Passkey' })
  expect(
    passkey.compareDocumentPosition(oidc) & Node.DOCUMENT_POSITION_FOLLOWING
  ).toBeTruthy()
  expect(screen.getAllByText('Or continue with')).toHaveLength(1)
})
