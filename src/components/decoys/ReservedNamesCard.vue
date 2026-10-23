<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { CheckRef, ReservedNames } from '../../types.ts'

import { mdiAccountCancelOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref } from 'vue'
import CheckStateNote from '../common/CheckStateNote.vue'
import ListEditor from '../common/ListEditor.vue'
import SectionCard from '../common/SectionCard.vue'
import { useAction } from '../../composables/useAction.ts'
import { errorMessage } from '../../services/api.ts'
import { changeReservedNames } from '../../stores/blocks.ts'
import { APP_ID } from '../../utils/format.ts'
import { isLoginName } from '../../utils/validate.ts'

const props = defineProps<{
	reserved: ReservedNames
	check: CheckRef
}>()

const { busy, run } = useAction()
const error = ref<string | null>(null)

const problems = computed(() => Object.fromEntries(props.reserved.collisions.map((name) => [
	name,
	t(APP_ID, 'An account with this name exists now, so it is skipped. Remove it.'),
])))

/**
 * @param value - A name as typed
 */
function validate(value: string): string | null {
	const max = props.reserved.limits.maxLength
	return isLoginName(value, max) ? null : t(APP_ID, 'A login name has no spaces and at most {max} characters.', { max })
}

/**
 * @param change - What to change
 * @param change.add - Names to reserve
 * @param change.remove - Names to release
 */
function change(change: { add?: string[], remove?: string[] }) {
	const fallback = t(APP_ID, 'The names could not be saved. Please try again.')
	error.value = null
	run('names', () => changeReservedNames(change), {
		done: change.add
			? t(APP_ID, 'Reserved: {names}', { names: change.add.join(', ') }, undefined, { escape: false, sanitize: false })
			: t(APP_ID, 'Released: {names}', { names: (change.remove ?? []).join(', ') }, undefined, { escape: false, sanitize: false }),
		fallback,
		handle: (e) => {
			error.value = errorMessage(e, fallback)
			return true
		},
	})
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Reserved names')" :icon="mdiAccountCancelOutline">
		<template #description>
			{{ t(APP_ID, 'Account names like "admin" or "root" that no account here uses. Attack tools try them first, so the first login with one blocks the address.') }}
		</template>
		<template #actions>
			<CheckStateNote :check="check" />
		</template>
		<ListEditor
			:items="reserved.names"
			:label="t(APP_ID, 'Reserve a name')"
			:placeholder="t(APP_ID, 'e.g. {example}', { example: 'administrator' })"
			:validate="validate"
			:normalise="(value) => value.trim().toLowerCase()"
			:suggestions="reserved.suggestions"
			:suggestionsLabel="t(APP_ID, 'Common names no account here uses:')"
			:problems="problems"
			:emptyText="t(APP_ID, 'No name is reserved yet.')"
			:max="reserved.max"
			:busy="busy !== null"
			:error="error"
			@add="change({ add: $event })"
			@remove="change({ remove: [$event] })" />
		<p :class="$style.note">
			{{ t(APP_ID, 'Names of existing accounts cannot be reserved. If an account with a reserved name appears later, for example from LDAP, the name is skipped and the setup checks report it.') }}
		</p>
	</SectionCard>
</template>

<style module>
.note {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	font-size: 0.9em;
	line-height: 1.5;
}
</style>
