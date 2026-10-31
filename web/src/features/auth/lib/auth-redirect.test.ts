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
import { describe, expect, test } from 'vitest'

import { isConsoleRouteAllowed } from '@/lib/nav-modules'
import type { AuthUser } from '@/stores/auth-store'

import {
  getSavedLanguage,
  resolveLoginRedirect,
  sanitizeAuthRedirect,
} from './auth-redirect'

const origin = 'https://dashboard.example.com'

describe('authentication redirect validation', () => {
  test('preserves safe internal paths, search parameters, and fragments', () => {
    expect(sanitizeAuthRedirect('/console?tab=usage#recent', origin)).toBe(
      '/console?tab=usage#recent'
    )
    expect(
      sanitizeAuthRedirect(
        'https://dashboard.example.com/dashboard?tab=quota#daily',
        origin
      )
    ).toBe('/dashboard?tab=quota#daily')
  })

  test('rejects external and ambiguously parsed redirect targets', () => {
    const unsafeTargets: unknown[] = [
      undefined,
      '',
      'dashboard',
      '//attacker.example/path',
      'https://attacker.example/path',
      'javascript:alert(1)',
      '/\\attacker.example/path',
      'https:\\attacker.example/path',
    ]

    for (const target of unsafeTargets) {
      expect(sanitizeAuthRedirect(target, origin)).toBe(null)
    }
  })

  test('rejects invalid or non-HTTP application origins', () => {
    expect(sanitizeAuthRedirect('/dashboard', 'not-an-origin')).toBe(null)
    expect(sanitizeAuthRedirect('/dashboard', 'file:///tmp/app')).toBe(null)
  })
})

describe('saved authentication language', () => {
  const user: AuthUser = { id: 1, username: 'user', role: 1 }

  test('prefers the explicit user language', () => {
    expect(
      getSavedLanguage({
        ...user,
        language: 'ja',
        setting: { language: 'fr' },
      })
    ).toBe('ja')
  })

  test('reads object and JSON string settings', () => {
    expect(getSavedLanguage({ ...user, setting: { language: 'fr' } })).toBe(
      'fr'
    )
    expect(getSavedLanguage({ ...user, setting: '{"language":"ru"}' })).toBe(
      'ru'
    )
  })

  test('ignores malformed and non-string setting languages', () => {
    expect(getSavedLanguage({ ...user, setting: '{' })).toBe(undefined)
    expect(getSavedLanguage({ ...user, setting: { language: 123 } })).toBe(
      undefined
    )
  })
})

describe('model service console navigation', () => {
  const user: AuthUser = {
    id: 1,
    username: 'user',
    role: 1,
    permissions: { model_service_only: true },
  }

  test('preserves organization key and model detail destinations', () => {
    for (const target of [
      '/keys?workspace_key=org%3Aexample',
      '/pricing/deepseek-flash',
      '/usage-logs/common',
    ]) {
      expect(resolveLoginRedirect(user, target, origin)).toBe(target)
      expect(isConsoleRouteAllowed(user, target)).toBe(true)
    }
  })

  test('direct routes and login returns cannot reopen hidden account pages', () => {
    for (const target of [
      '/profile',
      '/wallet?show_history=true',
      '/security',
      '/dashboard',
      '/console/personal',
      '/keys-other',
      '/usage-logs/audit',
      '/usage-logs/task',
      '/usage-logs/drawing',
      '/usage-logs/new-feature',
      '/pricing/model/new-feature',
    ]) {
      expect(isConsoleRouteAllowed(user, target)).toBe(false)
      expect(resolveLoginRedirect(user, target, origin)).toBe('/keys')
    }
    expect(resolveLoginRedirect(user, undefined, origin)).toBe('/keys')
    expect(
      resolveLoginRedirect(
        { ...user, role: 100, permissions: { model_service_only: false } },
        '/security',
        origin
      )
    ).toBe('/security')
  })
})
