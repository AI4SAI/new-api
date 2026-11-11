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

import {
  managedAccountContextSchema,
  memberCandidatesSchema,
  type ApiKey,
  type ApiResponse,
  type GetApiKeysParams,
  type GetApiKeysResponse,
  type SearchApiKeysParams,
  type ApiKeyFormData,
  type TokenAutoGroupsConfig,
  type ManagedAccountContext,
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
  const parsed = managedAccountContextSchema.safeParse(response.data)
  if (!parsed.success || parsed.data.workspace_key !== workspaceKey) {
    throw new Error('Invalid model account context')
  }
  return parsed.data
}

export async function getMemberCandidates(
  workspaceKey: string,
  query = '',
  after = '',
  signal?: AbortSignal
) {
  const params = new URLSearchParams({ query, after, limit: '50' })
  const response = requireServerSuccess(
    (
      await api.get(
        `/api/token/member-candidates?${params}`,
        modelAccountRequest(workspaceKey, signal)
      )
    ).data
  )
  return memberCandidatesSchema.parse(response.data)
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
  const { p = 1, size = 10, subject_ref } = params
  const query = new URLSearchParams({ p: String(p), size: String(size) })
  if (subject_ref) query.set('subject_ref', subject_ref)
  const res = await api.get(
    `/api/token/?${query}`,
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
  if (params.subject_ref) queryParams.set('subject_ref', params.subject_ref)
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
  data: Partial<ApiKeyFormData> & { id: number },
  workspaceKey?: string
): Promise<ApiResponse<ApiKey>> {
  const res = await api.put(
    '/api/token/',
    data,
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
