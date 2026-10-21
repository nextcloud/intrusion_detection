<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '@nextcloud/l10n'
import { ref, useId, watch } from 'vue'
import { APP_ID, DURATION_UNITS, splitDuration } from '../../utils/format.ts'

/** Seconds; text that is not a number is passed on as typed, so validation can say what is wrong */
const model = defineModel<number | string>({ required: true })

defineProps<{
	label: string
	describedby?: string
	invalid?: boolean
	disabled?: boolean
}>()

const id = useId()
const amount = ref('')
const unit = ref(1)

watch(model, (value) => {
	if (typeof value === 'number' && Number.isFinite(value)) {
		const current = /^\d+$/.test(amount.value.trim()) ? Number(amount.value) * unit.value : NaN
		if (current !== value) {
			const split = splitDuration(value)
			amount.value = String(split.amount)
			unit.value = split.unit
		}
	}
}, { immediate: true })

/**
 * Combine the number and the unit into seconds.
 */
function emitValue() {
	const text = amount.value.trim()
	model.value = /^\d{1,9}$/.test(text) ? Number(text) * unit.value : text
}
</script>

<template>
	<div :class="$style.duration">
		<label :for="id" :class="$style.duration__label">{{ label }}</label>
		<div :class="[$style.duration__row, { [$style.duration__row_invalid]: invalid }]">
			<input
				:id="id"
				v-model="amount"
				:class="$style.duration__amount"
				type="text"
				inputmode="numeric"
				autocomplete="off"
				:disabled="disabled"
				:aria-invalid="invalid ? 'true' : undefined"
				:aria-describedby="describedby"
				@input="emitValue">
			<select
				v-model.number="unit"
				:class="$style.duration__unit"
				:disabled="disabled"
				:aria-label="t(APP_ID, 'Unit of {setting}', { setting: label })"
				@change="emitValue">
				<option v-for="option in DURATION_UNITS" :key="option.seconds" :value="option.seconds">
					{{ option.label() }}
				</option>
			</select>
		</div>
	</div>
</template>

<style module>
.duration {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.duration__label {
	font-weight: 600;
}

.duration__row {
	display: flex;
	max-width: 300px;
}

.duration__row input.duration__amount {
	flex: 1 1 80px;
	min-width: 0;
	margin: 0;
	border-start-end-radius: 0 !important;
	border-end-end-radius: 0 !important;
	font-variant-numeric: tabular-nums;
}

.duration__row select.duration__unit {
	flex: 0 1 auto;
	margin: 0;
	margin-inline-start: -2px;
	border-start-start-radius: 0 !important;
	border-end-start-radius: 0 !important;
}

.duration__row_invalid input.duration__amount {
	border-color: var(--color-border-error, var(--color-error)) !important;
}
</style>
