<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextArea from '@nextcloud/vue/components/NcTextArea'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, isCancelled, liftBan } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { refreshStatus } from '../../store.ts'
import { APP_ID, formatAddress } from '../../utils/format.ts'

const props = defineProps<{
	ban: Ban | null
}>()

const emit = defineEmits<{
	close: []
	lifted: [ban: Ban]
}>()

const note = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const { announce } = useAnnouncer()

watch(() => props.ban, () => {
	note.value = ''
	error.value = null
})

const open = computed({
	get: () => props.ban !== null,
	set: (value: boolean) => {
		if (!value) {
			emit('close')
		}
	},
})

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	// Returning false keeps the dialog open; the form's submit event does the work.
	{ label: t(APP_ID, 'Lift block'), variant: 'primary' as const, type: 'submit' as const, disabled: note.value.trim() === '' || busy.value, callback: () => false },
])

/**
 * Lift the block with the note.
 */
async function submit() {
	if (props.ban === null || note.value.trim() === '') {
		return
	}
	busy.value = true
	error.value = null
	try {
		const lifted = await liftBan(props.ban.id, note.value.trim())
		announce(t(APP_ID, 'The block of {address} was lifted.', { address: formatAddress(lifted.cidr) }))
		emit('lifted', lifted)
		emit('close')
		refreshStatus()
	} catch (e) {
		if (!isCancelled(e)) {
			logger.error('Could not lift the block', { error: e })
			error.value = errorMessage(e, t(APP_ID, 'The block could not be lifted. Please try again.'))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Lift the block of {address}?', { address: ban ? formatAddress(ban.cidr) : '' })"
		isForm
		:buttons="buttons"
		size="normal"
		@submit="submit">
		<div :class="$style.dialog">
			<p>{{ t(APP_ID, 'Visitors from this address can reach the server again at once. If the address attacks again, the next block lasts longer.') }}</p>
			<NcTextArea
				v-model="note"
				:label="t(APP_ID, 'Why are you lifting it?')"
				:helperText="t(APP_ID, 'Required. Kept with the block and in the audit log.')"
				resize="vertical"
				required />
			<NcNoteCard v-if="error" type="error" :text="error" />
		</div>
	</NcDialog>
</template>

<style module>
.dialog {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-bottom: calc(var(--default-grid-baseline) * 2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}
</style>
