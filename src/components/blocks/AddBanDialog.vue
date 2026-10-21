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
import NcTextField from '@nextcloud/vue/components/NcTextField'
import DurationInput from '../checks/DurationInput.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { addBan, ApiError, errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { globalValues, refreshStatus, state } from '../../store.ts'
import { APP_ID, formatDuration } from '../../utils/format.ts'
import { isCidr } from '../../utils/validate.ts'

const open = defineModel<boolean>('open', { required: true })

const emit = defineEmits<{
	added: [ban: Ban]
}>()

const target = ref('')
const length = ref<'level' | 'custom'>('level')
const level = ref(1)
const duration = ref<number | string>(3600)
const note = ref('')
const errors = ref<Partial<Record<string, string>>>({})
const error = ref<string | null>(null)
const busy = ref(false)
const { announce } = useAnnouncer()

watch(open, (value) => {
	if (value) {
		target.value = ''
		length.value = 'level'
		level.value = 1
		duration.value = 3600
		note.value = ''
		errors.value = {}
		error.value = null
	}
})

// A refusal from the server is about the value it was given; a new value gets a fresh chance.
watch(target, () => {
	errors.value = { ...errors.value, target: undefined }
})
watch(duration, () => {
	errors.value = { ...errors.value, duration: undefined }
})

const levels = computed(() => [1, 2, 3].map((value) => ({
	value,
	label: {
		1: t(APP_ID, 'First block: {duration}', { duration: formatDuration(Number(globalValues.value.ban_duration_1 ?? 14400)) }),
		2: t(APP_ID, 'Second block: {duration}', { duration: formatDuration(Number(globalValues.value.ban_duration_2 ?? 86400)) }),
		3: t(APP_ID, 'Repeat offender: {duration}', { duration: formatDuration(Number(globalValues.value.ban_duration_3 ?? 604800)) }),
	}[value]!,
})))

const targetError = computed(() => {
	const value = target.value.trim()
	if (value === '' || isCidr(value)) {
		return errors.value.target ?? null
	}
	return t(APP_ID, 'Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.')
})

const durationError = computed(() => {
	if (length.value !== 'custom') {
		return null
	}
	const seconds = duration.value
	if (typeof seconds !== 'number') {
		return t(APP_ID, 'Enter a whole number.')
	}
	if (seconds < 300 || seconds > 90 * 86400) {
		return t(APP_ID, 'A block lasts from 5 minutes to 90 days.')
	}
	return errors.value.duration ?? null
})

const valid = computed(() => target.value.trim() !== '' && targetError.value === null && durationError.value === null && note.value.length <= 255)

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Block address'), variant: 'primary' as const, type: 'submit' as const, disabled: !valid.value || busy.value, callback: () => false },
])

/**
 * Add the block.
 */
async function submit() {
	if (!valid.value) {
		return
	}
	busy.value = true
	errors.value = {}
	error.value = null
	try {
		const ban = await addBan({
			target: target.value.trim(),
			level: level.value,
			duration: length.value === 'custom' && typeof duration.value === 'number' ? duration.value : undefined,
			note: note.value.trim(),
		})
		announce(t(APP_ID, '{address} is blocked. Reference {reference}.', { address: ban.cidr, reference: ban.reference }))
		emit('added', ban)
		open.value = false
		refreshStatus()
	} catch (e) {
		if (isCancelled(e)) {
			return
		}
		logger.error('Could not add the block', { error: e })
		if (e instanceof ApiError && (e.param === 'target' || e.param === 'duration')) {
			errors.value = { [e.param]: e.message }
		} else {
			error.value = errorMessage(e, t(APP_ID, 'The address could not be blocked. Please try again.'))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Block an address')"
		isForm
		:buttons="buttons"
		size="normal"
		@submit="submit">
		<div :class="$style.dialog">
			<p>{{ t(APP_ID, 'Requests from the address get an error page with a reference until the block ends. A whole network can be blocked as a /24 (IPv4) or /64 (IPv6).') }}</p>
			<NcTextField
				v-model="target"
				:label="t(APP_ID, 'Address or network')"
				placeholder="203.0.113.7"
				autocomplete="off"
				spellcheck="false"
				:error="targetError !== null"
				:helperText="targetError ?? (state.ownAddress ? t(APP_ID, 'Your own address {address} cannot be blocked.', { address: state.ownAddress }) : '')"
				required />

			<fieldset :class="$style.dialog__fieldset">
				<legend :class="$style.dialog__legend">
					{{ t(APP_ID, 'How long') }}
				</legend>
				<label :class="$style.dialog__radio">
					<input v-model="length" type="radio" value="level">
					<span>{{ t(APP_ID, 'Like an automatic block') }}</span>
				</label>
				<select
					v-if="length === 'level'"
					v-model.number="level"
					:class="$style.dialog__select"
					:aria-label="t(APP_ID, 'Escalation level')">
					<option v-for="option in levels" :key="option.value" :value="option.value">
						{{ option.label }}
					</option>
				</select>
				<label :class="$style.dialog__radio">
					<input v-model="length" type="radio" value="custom">
					<span>{{ t(APP_ID, 'For a time I choose') }}</span>
				</label>
				<template v-if="length === 'custom'">
					<DurationInput v-model="duration" :label="t(APP_ID, 'Duration')" :invalid="durationError !== null" />
					<p v-if="durationError" :class="$style.dialog__error">
						{{ durationError }}
					</p>
				</template>
			</fieldset>

			<NcTextArea
				v-model="note"
				:label="t(APP_ID, 'Note (optional)')"
				:helperText="t(APP_ID, 'Why the address is blocked, for other administrators. Kept with the block and in the audit log.')"
				:error="note.length > 255"
				resize="vertical" />

			<NcNoteCard v-if="error" type="error" :text="error" />
		</div>
	</NcDialog>
</template>

<style module>
.dialog {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	padding-bottom: calc(var(--default-grid-baseline) * 2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}

.dialog__fieldset {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	border: none;
}

.dialog__legend {
	margin-bottom: calc(var(--default-grid-baseline) * 1);
	padding: 0;
	font-weight: 600;
}

.dialog__radio {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	cursor: pointer;
}

.dialog__radio input {
	margin: 0;
	accent-color: var(--color-primary-element);
}

.dialog__select {
	max-width: 320px;
	margin: 0;
	margin-inline-start: calc(var(--default-grid-baseline) * 6);
}

.dialog__error {
	color: var(--color-error-text);
	font-weight: 600;
}
</style>
