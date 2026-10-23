<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, ref, useId, watch } from 'vue'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import SelectField from '../common/SelectField.vue'
import { APP_ID, DURATION_UNITS, splitDuration } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

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

const units = computed(() => DURATION_UNITS.map((option) => ({ value: option.seconds, label: option.label() })))

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
		<div :class="$style.duration__row">
			<NcTextField
				:id="id"
				v-model="amount"
				:class="$style.duration__amount"
				labelOutside
				inputmode="numeric"
				autocomplete="off"
				:disabled="disabled"
				:error="invalid"
				:aria-describedby="describedby"
				@update:modelValue="emitValue" />
			<SelectField
				v-model="unit"
				:class="$style.duration__unit"
				:options="units"
				:label="t(APP_ID, 'Unit of {setting}', { setting: label })"
				hideLabel
				:disabled="disabled"
				@update:modelValue="emitValue" />
		</div>
	</div>
</template>

<style module>
.duration {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
}

.duration__label {
	font-weight: 600;
}

.duration__row {
	display: flex;
	align-items: center;
	gap: var(--ids-space-2);
	max-width: 360px;
}

.duration__amount {
	flex: 1 1 90px;
	min-width: 0;
	font-variant-numeric: tabular-nums;
}

.duration__unit {
	flex: 1 1 130px;
	min-width: 0;
}
</style>
