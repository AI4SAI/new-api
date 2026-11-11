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
import { useInfiniteQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { LoadingState } from '@/components/loading-state'
import { Button } from '@/components/ui/button'
import {
  Combobox,
  ComboboxContent,
  ComboboxEmpty,
  ComboboxInput,
  ComboboxItem,
  ComboboxList,
} from '@/components/ui/combobox'
import { useDebounce } from '@/hooks/use-debounce'

import { getMemberCandidates } from '../api'
import type { MemberCandidate } from '../types'

export function MemberCandidateSelect(props: {
  workspaceKey: string
  scopeKey: string
  value: MemberCandidate | null
  onChange: (value: MemberCandidate | null) => void
  allowClear?: boolean
  id?: string
  'aria-invalid'?: boolean | 'true' | 'false'
  'aria-describedby'?: string
}) {
  const { t } = useTranslation()
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const query = useDebounce(search, 300)
  const candidates = useInfiniteQuery({
    queryKey: ['model-member-candidates', props.scopeKey, query],
    queryFn: ({ pageParam, signal }) =>
      getMemberCandidates(props.workspaceKey, query, pageParam, signal),
    initialPageParam: '',
    getNextPageParam: (page) => page.next_cursor || undefined,
    enabled: open,
    staleTime: 0,
    gcTime: 0,
    retry: false,
    meta: { errorToast: false },
  })
  const searching = search !== query || candidates.isPending
  const items = searching
    ? []
    : (candidates.data?.pages.flatMap((page) => page.items) ?? [])
  const selectedLabel = props.value?.display_name || props.value?.username || ''

  return (
    <Combobox
      items={items}
      value={props.value}
      open={open}
      onOpenChange={(nextOpen) => {
        setOpen(nextOpen)
        if (!nextOpen) setSearch('')
      }}
      inputValue={open ? search : selectedLabel}
      onInputValueChange={(value, details) => {
        if (details.reason === 'input-change') setSearch(value)
      }}
      onValueChange={props.onChange}
      itemToStringLabel={(member) =>
        member.display_name || member.username || t('Member')
      }
      isItemEqualToValue={(a, b) => a.subject_ref === b.subject_ref}
      filter={null}
    >
      <ComboboxInput
        id={props.id}
        aria-label={t('Member')}
        aria-invalid={props['aria-invalid']}
        aria-describedby={props['aria-describedby']}
        maxLength={80}
        placeholder={props.allowClear ? t('All members') : t('Select a member')}
        triggerAriaLabel={t('Select a member')}
        showClear={props.allowClear}
        className='w-full'
      />
      <ComboboxContent>
        {candidates.isError ? (
          <ErrorState
            className='min-h-0'
            onRetry={() => void candidates.refetch()}
          />
        ) : (
          <>
            {searching && <LoadingState inline size='sm' />}
            {!searching && !candidates.hasNextPage && (
              <ComboboxEmpty>{t('No results found')}</ComboboxEmpty>
            )}
            <ComboboxList>
              {(member: MemberCandidate) => (
                <ComboboxItem key={member.subject_ref} value={member}>
                  <span className='min-w-0 break-words'>
                    {member.display_name || member.username || t('Member')}
                    {member.display_name &&
                      member.username &&
                      member.username !== member.display_name && (
                        <span className='text-muted-foreground block text-xs break-all'>
                          {member.username}
                        </span>
                      )}
                  </span>
                </ComboboxItem>
              )}
            </ComboboxList>
            {candidates.hasNextPage && (
              <Button
                type='button'
                variant='ghost'
                className='w-full'
                disabled={candidates.isFetchingNextPage}
                onClick={() => void candidates.fetchNextPage()}
              >
                {candidates.isFetchingNextPage
                  ? t('Loading...')
                  : t('Load more')}
              </Button>
            )}
          </>
        )}
      </ComboboxContent>
    </Combobox>
  )
}
