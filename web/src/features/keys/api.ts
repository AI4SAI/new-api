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
import { api } from '@/lib/api'
import { requireServerSuccess } from '@/lib/server-error-message'

import type {
  ApiKey,
  ApiResponse,
  GetApiKeysParams,
  GetApiKeysResponse,
  SearchApiKeysParams,
  ApiKeyFormData,
  TokenAutoGroupsConfig,
  ManagedAccountContext,
} from './types'

export function modelAccountRequest(
  workspaceKey?: string,
  signal?: AbortSignal
) {
  return {
    signal,
    // The shared GET deduplicator keys only by session and URL, not headers.
    disableDuplicate: Boolean(workspaceKey),
    headers: workspaceKey ? { 'X-SAI-Workspace-Key': workspaceKey } : undefined,
  }
}

export async function getManagedAccountContext(
  workspaceKey: string,
  signal?: AbortSignal
): Promise<ManagedAccountContext> {
  const response = requireServerSuccess(
    (
      await api.get(
        '/api/token/context',
        modelAccountRequest(workspaceKey, signal)
      )
    ).data
  )
  const value = response.data as ManagedAccountContext
  if (
    !value ||
    value.workspace_key !== workspaceKey ||
    !Number.isSafeInteger(value.native_owner_id) ||
    value.native_owner_id <= 0 ||
    typeof value.account_label !== 'string' ||
    !value.account_label ||
    !['org', 'project'].includes(value.account_kind)
  ) {
    throw new Error('Invalid model account context')
  }
  return value
}

// ============================================================================
// API Key Management
// ============================================================================

// Get paginated API keys list
export async function getApiKeys(
  params: GetApiKeysParams = {},
  workspaceKey?: string,
  signal?: AbortSignal
): Promise<GetApiKeysResponse> {
  const { p = 1, size = 10 } = params
  const res = await api.get(
    `/api/token/?p=${p}&size=${size}`,
    modelAccountRequest(workspaceKey, signal)
  )
  return res.data
}

// Search API keys by keyword or token (with pagination)
export async function searchApiKeys(
  params: SearchApiKeysParams,
  workspaceKey?: string,
  signal?: AbortSignal
): Promise<GetApiKeysResponse> {
  const { keyword = '', token = '', p, size } = params
  const queryParams = new URLSearchParams()
  if (keyword) queryParams.set('keyword', keyword)
  if (token) queryParams.set('token', token)
  if (p != null) queryParams.set('p', String(p))
  if (size != null) queryParams.set('size', String(size))
  const res = await api.get(
    `/api/token/search?${queryParams.toString()}`,
    modelAccountRequest(workspaceKey, signal)
  )
  return res.data
}

// Get single API key by ID
export async function getApiKey(
  id: number,
  workspaceKey?: string
): Promise<ApiResponse<ApiKey>> {
  const res = await api.get(
    `/api/token/${id}`,
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Get the current user's global Auto order and the per-token selection limit.
export async function getTokenAutoGroups(
  workspaceKey?: string
): Promise<ApiResponse<TokenAutoGroupsConfig>> {
  const res = await api.get(
    '/api/token/auto-groups',
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Create a new API key
export async function createApiKey(
  data: ApiKeyFormData,
  workspaceKey: string | undefined,
  requestId: string
): Promise<ApiResponse<ApiKey>> {
  const res = await api.post('/api/token/', data, {
    ...modelAccountRequest(workspaceKey),
    headers: {
      ...modelAccountRequest(workspaceKey).headers,
      'Idempotency-Key': requestId,
    },
  })
  return res.data
}

// Update an existing API key
export async function updateApiKey(
  data: ApiKeyFormData & { id: number },
  workspaceKey?: string
): Promise<ApiResponse<ApiKey>> {
  const res = await api.put(
    '/api/token/',
    data,
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Delete a single API key
export async function deleteApiKey(
  id: number,
  workspaceKey?: string
): Promise<ApiResponse> {
  const res = await api.delete(
    `/api/token/${id}/`,
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Batch delete multiple API keys
export async function batchDeleteApiKeys(
  ids: number[],
  workspaceKey?: string
): Promise<ApiResponse<number>> {
  const res = await api.post(
    '/api/token/batch',
    { ids },
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Update API key status (enable/disable)
export async function updateApiKeyStatus(
  id: number,
  status: number,
  workspaceKey?: string
): Promise<ApiResponse<ApiKey>> {
  const res = await api.put(
    '/api/token/?status_only=true',
    { id, status },
    modelAccountRequest(workspaceKey)
  )
  return res.data
}

// Fetch the real (unmasked) key for a token by ID
export async function fetchTokenKey(
  id: number,
  workspaceKey?: string,
  signal?: AbortSignal
): Promise<{ success: boolean; message?: string; data?: { key: string } }> {
  const res = await api.post(
    `/api/token/${id}/key`,
    undefined,
    modelAccountRequest(workspaceKey, signal)
  )
  return res.data
}

// Batch fetch real (unmasked) keys for multiple tokens
export async function fetchTokenKeysBatch(
  ids: number[],
  workspaceKey?: string,
  signal?: AbortSignal
): Promise<{
  success: boolean
  message?: string
  data?: { keys: Record<number, string> }
}> {
  const res = await api.post(
    '/api/token/batch/keys',
    { ids },
    modelAccountRequest(workspaceKey, signal)
  )
  return res.data
}
