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
import { useQuery } from '@tanstack/react-query'
import axios from 'axios'
import { Fragment, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { useAuthStore } from '@/stores/auth-store'

import { getManagedAccountContext } from '../api'
import type { ManagedAccountContext } from '../types'

export function ManagedAccountBoundary(props: {
  workspaceKey?: string
  children: (
    account: ManagedAccountContext | undefined,
    scopeKey: string
  ) => ReactNode
}) {
  const { t } = useTranslation()
  const session = useAuthStore((state) => state.auth.session)
  const user = useAuthStore((state) => state.auth.user)
  const scopeKey = JSON.stringify([
    session?.sid,
    user?.id,
    props.workspaceKey ?? '',
  ])
  const context = useQuery({
    queryKey: ['model-account-context', scopeKey],
    queryFn: ({ signal }) => {
      if (!props.workspaceKey) {
        throw new Error('Model account context is missing')
      }
      return getManagedAccountContext(props.workspaceKey, signal)
    },
    enabled: Boolean(props.workspaceKey),
    retry: false,
    staleTime: 0,
    gcTime: 0,
    refetchOnWindowFocus: false,
    meta: { errorToast: false },
  })
  if (props.workspaceKey && (context.isPending || context.isFetching)) {
    return <LoadingState />
  }
  if (props.workspaceKey && context.isError) {
    const status = axios.isAxiosError(context.error)
      ? context.error.response?.status
      : undefined
    return (
      <ErrorState
        title={
          status === 403 ? t('Access denied') : t('Model account unavailable')
        }
        onRetry={() => void context.refetch()}
      />
    )
  }
  return (
    <Fragment key={scopeKey}>{props.children(context.data, scopeKey)}</Fragment>
  )
}
