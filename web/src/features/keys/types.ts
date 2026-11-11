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
import { z } from 'zod'

export const managedAccountContextSchema = z.object({
  workspace_key: z.string(),
  native_owner_id: z.number().int().positive().safe(),
  account_label: z.string().min(1),
  account_kind: z.enum(['org', 'project']),
  resource_scope: z.discriminatedUnion('kind', [
    z.object({ kind: z.literal('all'), subject_ref: z.literal('') }),
    z.object({ kind: z.literal('subject'), subject_ref: z.uuid() }),
  ]),
  allowed_actions: z.array(z.string()),
  allowed_update_fields: z.array(z.string()),
  allowed_statuses: z.array(z.number().int()),
})

export type ManagedAccountContext = z.infer<typeof managedAccountContextSchema>

export const memberCandidatesSchema = z.object({
  items: z.array(
    z.object({
      subject_ref: z.uuid(),
      display_name: z.string(),
      username: z.string(),
    })
  ),
  next_cursor: z.string(),
})

export type MemberCandidate = z.infer<
  typeof memberCandidatesSchema
>['items'][number]

// ============================================================================
// API Key Schema & Types
// ============================================================================

export const apiKeySchema = z.object({
  id: z.number(),
  name: z.string(),
  key: z.string(),
  managed: z.boolean().optional(),
  attribution: z
    .discriminatedUnion('state', [
      z.object({ state: z.literal('unknown') }),
      z.object({ state: z.literal('unavailable') }),
      z.object({
        state: z.literal('ready'),
        actor: z.object({ display_name: z.string(), username: z.string() }),
        workspace: z.object({
          kind: z.enum(['org', 'project']),
          code: z.string(),
          label: z.string(),
        }),
      }),
    ])
    .optional(),
  status: z.number(), // 1: enabled, 2: disabled, 3: expired, 4: exhausted
  remain_quota: z.number(),
  used_quota: z.number(),
  quota_revision: z.number().int().nonnegative().optional().default(0),
  unlimited_quota: z.boolean(),
  expired_time: z.number(), // -1 for never expires
  created_time: z.number(),
  accessed_time: z.number(),
  group: z.string().nullish().default(''),
  auto_groups: z.array(z.string()).nullish().default(null),
  cross_group_retry: z
    .preprocess((v) => {
      if (v === 1) return true
      if (v === 0) return false
      return v
    }, z.boolean())
    .optional()
    .default(false),
  model_limits_enabled: z.boolean(),
  model_limits: z.string().nullish().default(''),
  allow_ips: z.string().nullish().default(''),
  allow_user_quota_query: z.boolean().optional().default(false),
})

export type ApiKey = z.infer<typeof apiKeySchema>

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
}

export interface GetApiKeysParams {
  subject_ref?: string
  p?: number
  size?: number
}

export interface GetApiKeysResponse {
  success: boolean
  message?: string
  data?: {
    items: ApiKey[]
    total: number
    page: number
    page_size: number
  }
}

export interface SearchApiKeysParams {
  subject_ref?: string
  keyword?: string
  token?: string
  p?: number
  size?: number
}

export interface ApiKeyFormData {
  name: string
  assignee_ref?: string
  remain_quota?: number
  quota_delta?: number
  expected_quota_revision?: number
  expired_time: number
  unlimited_quota: boolean
  model_limits_enabled: boolean
  model_limits: string
  allow_ips: string
  allow_user_quota_query: boolean
  group: string
  auto_groups: string[]
  cross_group_retry: boolean
}

export interface TokenAutoGroupsConfig {
  groups: string[]
  max_count: number
}

// ============================================================================
// Dialog Types
// ============================================================================

export type ApiKeysDialogType = 'create' | 'update' | 'cc-switch'
