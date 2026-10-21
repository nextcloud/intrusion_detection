<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Lockdown } from '../../types.ts'

import { mdiAccountAlertOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcSelect from '@nextcloud/vue/components/NcSelect'
import NcTextArea from '@nextcloud/vue/components/NcTextArea'
import { ApiError, errorMessage, fetchLockdown, isCancelled, startLockdown } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { globalTypes, globalValues } from '../../store.ts'
import { APP_ID, fillTemplateText, formatDuration } from '../../utils/format.ts'

const open = defineModel<boolean>('open', { required: true })

const emit = defineEmits<{
	started: [lockdown: Lockdown]
}>()

const HOUR = 3600

const lockdown = ref<Lockdown | null>(null)
const loadError = ref<string | null>(null)
const hours = ref(6)
const reason = ref('')
const effects = ref<string[]>([])
const error = ref<string | null>(null)
const reasonError = ref<string | null>(null)
const busy = ref(false)

watch(open, async (value) => {
	if (!value) {
		return
	}
	reason.value = ''
	error.value = null
	reasonError.value = null
	loadError.value = null
	try {
		const current = await fetchLockdown()
		lockdown.value = current
		hours.value = Math.round(current.defaultDuration / HOUR)
		effects.value = current.effects.filter((effect) => effect.enabled).map((effect) => effect.id)
	} catch (e) {
		logger.error('Could not load the lockdown settings', { error: e })
		loadError.value = errorMessage(e, t(APP_ID, 'The lockdown settings could not be loaded. Please try again.'))
	}
}, { immediate: true })

const durations = computed(() => {
	const min = (lockdown.value?.minDuration ?? HOUR) / HOUR
	const max = (lockdown.value?.maxDuration ?? 24 * HOUR) / HOUR
	return Array.from({ length: max - min + 1 }, (_, i) => ({ id: min + i, label: formatDuration((min + i) * HOUR) }))
})

const duration = computed({
	get: () => durations.value.find((option) => option.id === hours.value) ?? null,
	set: (option) => {
		if (option) {
			hours.value = option.id
		}
	},
})

const maxReason = computed(() => lockdown.value?.maxReason ?? 200)
const reasonTooLong = computed(() => new TextEncoder().encode(reason.value).length > maxReason.value)
const loginConfirmed = computed(() => effects.value.includes('login'))
const valid = computed(() => lockdown.value !== null && !reasonTooLong.value && !busy.value)

const buttons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'Start lockdown'), variant: 'error' as const, type: 'submit' as const, disabled: !valid.value, callback: () => false },
])

/**
 * @param id - An effect
 * @param on - Whether it is on for this lockdown
 */
function toggle(id: string, on: boolean) {
	effects.value = on ? [...new Set([...effects.value, id])] : effects.value.filter((effect) => effect !== id)
}

/**
 * @param template - A description with `{setting}` placeholders
 */
function fill(template: string): string {
	return fillTemplateText(template, globalValues.value, globalTypes.value)
}

/**
 * Start the lockdown.
 */
async function submit() {
	if (!valid.value) {
		return
	}
	busy.value = true
	error.value = null
	reasonError.value = null
	try {
		const started = await startLockdown(hours.value * HOUR, reason.value.trim(), effects.value)
		emit('started', started)
		open.value = false
	} catch (e) {
		if (isCancelled(e)) {
			return
		}
		logger.error('Could not start the lockdown', { error: e })
		if (e instanceof ApiError && e.param === 'reason') {
			reasonError.value = e.message
		} else {
			error.value = errorMessage(e, t(APP_ID, 'The lockdown could not be started. Please try again.'))
		}
	} finally {
		busy.value = false
	}
}
</script>

<template>
	<NcDialog
		v-model:open="open"
		:name="t(APP_ID, 'Start lockdown')"
		isForm
		:buttons="buttons"
		size="normal"
		@submit="submit">
		<div :class="$style.dialog">
			<p>{{ t(APP_ID, 'For when your server is under attack right now. Nextcloud asks for more confirmation and allows less, until the time is up or you end it. Every administrator is notified.') }}</p>

			<NcNoteCard v-if="loadError" type="error" :text="loadError" />
			<div v-else-if="lockdown === null" :class="$style.dialog__loading">
				<NcLoadingIcon :size="32" />
			</div>

			<template v-else>
				<NcSelect
					v-model="duration"
					:inputLabel="t(APP_ID, 'Duration')"
					:options="durations"
					:clearable="false"
					:searchable="false"
					label="label" />

				<NcTextArea
					v-model="reason"
					:label="t(APP_ID, 'Reason')"
					:placeholder="t(APP_ID, 'For example: credential stuffing from a botnet')"
					:helperText="reasonError ?? (reasonTooLong ? t(APP_ID, 'At most {max} characters.', { max: maxReason }) : t(APP_ID, 'Shown to the other administrators and kept in the audit log.'))"
					:error="reasonError !== null || reasonTooLong"
					resize="vertical" />

				<fieldset :class="$style.dialog__effects">
					<legend :class="$style.dialog__legend">
						{{ t(APP_ID, 'What the lockdown does') }}
					</legend>
					<p :class="$style.dialog__hint">
						{{ t(APP_ID, 'Your choice is kept for the next lockdown.') }}
					</p>
					<NcCheckboxRadioSwitch
						v-for="effect in lockdown.effects"
						:key="effect.id"
						type="switch"
						:modelValue="effects.includes(effect.id)"
						:description="fill(effect.description)"
						:data-effect="effect.id"
						@update:modelValue="toggle(effect.id, $event)">
						{{ effect.label }}
					</NcCheckboxRadioSwitch>
				</fieldset>

				<div v-if="loginConfirmed" :class="$style.dialog__impact" data-test="impact">
					<NcIconSvgWrapper :path="mdiAccountAlertOutline" :size="20" />
					<p>
						{{ n(APP_ID,
							'Users without a second factor or email address cannot log in with their password during lockdown: currently %n user. App passwords keep working.',
							'Users without a second factor or email address cannot log in with their password during lockdown: currently %n users. App passwords keep working.',
							lockdown.usersWithoutMethod) }}
					</p>
				</div>

				<p :class="$style.dialog__hint">
					{{ t(APP_ID, 'You can always end a lockdown here or with occ intrusion:lockdown --end, even if you cannot confirm a login yourself.') }}
				</p>
			</template>

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

.dialog__loading {
	display: flex;
	justify-content: center;
	padding: calc(var(--default-grid-baseline) * 6);
}

.dialog__effects {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding: 0;
	border: none;
}

.dialog__legend {
	margin-bottom: calc(var(--default-grid-baseline) * 1);
	padding: 0;
	font-weight: 600;
}

.dialog__impact {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-warning) 12%, var(--color-main-background));
	color: var(--color-main-text);
}

.dialog__impact > :first-child {
	flex: 0 0 auto;
	color: var(--color-warning-text);
}

.dialog__hint {
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}
</style>
