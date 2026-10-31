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
import { getRouteApi, Link } from '@tanstack/react-router'
import { useTranslation } from 'react-i18next'

import { SectionPageLayout } from '@/components/layout'
import { Button } from '@/components/ui/button'

import { ApiKeysDialogs } from './components/api-keys-dialogs'
import { ApiKeysPrimaryButtons } from './components/api-keys-primary-buttons'
import { ApiKeysProvider } from './components/api-keys-provider'
import { ApiKeysTable } from './components/api-keys-table'
import { ManagedAccountBoundary } from './components/managed-account-boundary'

export function ApiKeys() {
  const { t } = useTranslation()
  const workspaceKey = getRouteApi('/_authenticated/keys/').useSearch()
    .workspace_key
  return (
    <ManagedAccountBoundary workspaceKey={workspaceKey}>
      {(account, scopeKey) => (
        <ApiKeysProvider
          key={scopeKey}
          workspaceKey={workspaceKey}
          scopeKey={scopeKey}
        >
          <SectionPageLayout
            fixedContent
            stackActionsOnMobile={Boolean(workspaceKey)}
          >
            <SectionPageLayout.Title>
              {account
                ? `${account.account_label} · ${t('API Keys')}`
                : t('API Keys')}
            </SectionPageLayout.Title>
            <SectionPageLayout.Actions>
              {workspaceKey && (
                <Button
                  variant='outline'
                  render={
                    <Link
                      to='/usage-logs/$section'
                      params={{ section: 'common' }}
                      search={{ workspace_key: workspaceKey }}
                    />
                  }
                >
                  {t('Usage')}
                </Button>
              )}
              <ApiKeysPrimaryButtons />
            </SectionPageLayout.Actions>
            <SectionPageLayout.Content>
              <ApiKeysTable />
            </SectionPageLayout.Content>
          </SectionPageLayout>

          <ApiKeysDialogs />
        </ApiKeysProvider>
      )}
    </ManagedAccountBoundary>
  )
}
