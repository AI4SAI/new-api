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
import { retainSearchParams } from '@tanstack/react-router'
import { z } from 'zod'

// Navigation context only. The gateway authorizes every organization operation.
export const managedWorkspaceKeySchema = z
  .string()
  .regex(/^(org|project):[0-9a-f-]{36}$/)
  .optional()

export const modelWorkspaceSearchSchema = z.object({
  workspace_key: managedWorkspaceKeySchema,
})

export const modelWorkspaceSearch = {
  middlewares: [
    retainSearchParams<z.infer<typeof modelWorkspaceSearchSchema>>([
      'workspace_key',
    ]),
  ],
}
