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
import { createInstance } from 'i18next'
import { describe, expect, test } from 'vitest'

import { usageLogSchema } from '../../data/schema'
import { logTokenName } from '../format'

describe('usage log token name', () => {
  test('identifies managed usage with the same member and workspace as the key page', async () => {
    const i18n = createInstance()
    await i18n.init({ lng: 'en', resources: {} })
    const log = usageLogSchema.parse({
      id: 1,
      user_id: 41,
      created_at: 1,
      type: 2,
      content: '',
      token_id: 7,
      token_name: 'Pilot',
      attribution: {
        state: 'ready',
        actor: { display_name: 'Alice', username: 'alice' },
        workspace: {
          kind: 'project',
          code: 'proj-climate',
          label: 'Climate study',
        },
      },
    })
    expect(logTokenName(log, i18n.t)).toBe('Alice · Pilot · Climate study')
  })

  test('translates the name the gateway wrote when the log has no token', async () => {
    const i18n = createInstance()
    await i18n.init({
      lng: 'zh',
      resources: { zh: { translation: { 'Model test': '模型测试' } } },
    })

    expect(
      logTokenName({ token_id: 0, token_name: 'Model test' }, i18n.t)
    ).toBe('模型测试')
  })

  test('keeps the name of a real token as written when it equals a translation key', async () => {
    const i18n = createInstance()
    await i18n.init({
      lng: 'zh',
      resources: { zh: { translation: { 'Model test': '模型测试' } } },
    })

    expect(
      logTokenName({ token_id: 7, token_name: 'Model test' }, i18n.t)
    ).toBe('Model test')
  })
})
