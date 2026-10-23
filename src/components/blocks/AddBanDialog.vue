<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, BanLimits } from '../../types.ts'

import { computed, ref, watch } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcTextArea from '@nextcloud/vue/components/NcTextArea'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import DurationInput from '../checks/DurationInput.vue'
import SelectField from '../common/SelectField.vue'
import { useAction } from '../../composables/useAction.ts'
import { ApiError } from '../../services/api.ts'
import { banAdd, state } from '../../store.ts'
import { APP_ID, formatAddress, formatDuration } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { isCidr } from '../../utils/validate.ts'

const open = defineModel<boolean>('open', { required: true })

const props = defineProps<{
	/** The server's limits; the dialog waits for them */
	limits: BanLimits | null
}>()

const target = ref('')
const length = ref<'level' | 'custom'>('level')
const level = ref(1)
const duration = ref<number | string>(3600)
const note = ref('')
const errors = ref<Partial<Record<string, string>>>({})
const { busy, error, run } = useAction()

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

const levels = computed(() => (props.limits?.levelDurations ?? []).map((seconds, index) => ({
	value: index + 1,
	label: [
		t(APP_ID, 'First block: {duration}', { duration: formatDuration(seconds) }),
		t(APP_ID, 'Second block: {duration}', { duration: formatDuration(seconds) }),
		t(APP_ID, 'Repeat offender: {duration}', { duration: formatDuration(seconds) }),
	][index]!,
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
	if (props.limits !== null && (seconds < props.limits.minDuration || seconds > props.limits.maxDuration)) {
		return t(APP_ID, 'A block lasts from 5 minutes to 90 days.')
	}
	return errors.value.duration ?? null
})

const noteTooLong = computed(() => props.limits !== null && note.value.trim().length > props.limits.maxNote)
const valid = computed(() => props.limits !== null && target.value.trim() !== '' && targetError.value === null && durationError.value === null && !noteTooLong.value)

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Block address'), variant: 'primary' as const, type: 'submit' as const, disabled: !valid.value || busy.value !== null, callback: () => false },
])

/**
 * Add the block.
 */
async function submit() {
	if (!valid.value) {
		return
	}
	errors.value = {}
	const added = await run('add', () => banAdd({
		target: target.value.trim(),
		level: level.value,
		duration: length.value === 'custom' && typeof duration.value === 'number' ? duration.value : undefined,
		note: note.value.trim(),
	}), {
		done: (ban: Ban) => t(APP_ID, '{address} is blocked. Reference {reference}.', { address: formatAddress(ban.cidr), reference: ban.reference }),
		fallback: t(APP_ID, 'The address could not be blocked. Please try again.'),
		inline: true,
		handle: (e) => {
			if (e instanceof ApiError && (e.param === 'target' || e.param === 'duration')) {
				errors.value = { [e.param]: e.message }
				return true
			}
			return false
		},
	})
	if (added) {
		open.value = false
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
		<div :class="$style.dialog" @keydown.esc="open = false">
			<p>{{ t(APP_ID, 'Requests from the address get an error page with a reference until the block ends. A whole network can be blocked as a /24 (IPv4) or /64 (IPv6).') }}</p>
			<NcTextField
				v-model="target"
				:label="t(APP_ID, 'Address or network')"
				:placeholder="t(APP_ID, 'e.g. {example}', { example: '203.0.113.7' })"
				autocomplete="off"
				spellcheck="false"
				:error="targetError !== null"
				:helperText="targetError ?? (state.ownAddress ? t(APP_ID, 'Your own address {address} cannot be blocked.', { address: state.ownAddress }) : '')"
				required />

			<fieldset :class="$style.dialog__fieldset">
				<legend :class="$style.dialog__legend">
					{{ t(APP_ID, 'How long') }}
				</legend>
				<NcCheckboxRadioSwitch
					v-model="length"
					type="radio"
					value="level"
					name="ids-ban-length">
					{{ t(APP_ID, 'Like an automatic block') }}
				</NcCheckboxRadioSwitch>
				<SelectField
					v-if="length === 'level'"
					v-model="level"
					:class="$style.dialog__select"
					:label="t(APP_ID, 'Escalation level')"
					hideLabel
					:options="levels" />
				<NcCheckboxRadioSwitch
					v-model="length"
					type="radio"
					value="custom"
					name="ids-ban-length">
					{{ t(APP_ID, 'For a time I choose') }}
				</NcCheckboxRadioSwitch>
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
				:error="noteTooLong"
				resize="vertical" />

			<NcNoteCard v-if="error" type="error" :text="error" />
		</div>
	</NcDialog>
</template>

<style module>
.dialog {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	padding-bottom: var(--ids-space-2);
}

.dialog p {
	margin: 0;
	line-height: 1.5;
}

.dialog__fieldset {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	margin: 0;
	padding: 0;
	border: none;
}

.dialog__legend {
	margin-bottom: var(--ids-space-1);
	padding: 0;
	font-weight: 600;
}

.dialog__select {
	max-width: 320px;
	margin-inline-start: var(--ids-space-9);
}

.dialog__error {
	color: var(--color-error-text);
	font-weight: 600;
}
</style>
