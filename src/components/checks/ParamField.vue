<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Param } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import DurationInput from './DurationInput.vue'
import { APP_ID, choiceLabel, formatDuration, formatNumber, formatValue } from '../../utils/format.ts'

/** The field's raw value: what the admin typed, validated by the parent */
const model = defineModel<unknown>({ required: true })

const props = defineProps<{
	param: Param
	/** Shown under the field, before saving */
	error?: string | null
	disabled?: boolean
}>()

const id = useId()
const hintId = `${id}-hint`

const show = (value: number) => props.param.type === 'duration' ? formatDuration(value) : formatNumber(value)

const range = computed(() => {
	const { min, max } = props.param
	if (min !== null && max !== null) {
		return t(APP_ID, 'From {min} to {max}', { min: show(min), max: show(max) })
	}
	if (min !== null) {
		return t(APP_ID, 'At least {min}', { min: show(min) })
	}
	if (max !== null) {
		return t(APP_ID, 'At most {max}', { max: show(max) })
	}
	return ''
})

const hint = computed(() => [
	range.value,
	props.param.default === '' ? '' : t(APP_ID, 'default {value}', { value: formatValue(props.param.default, props.param.type) }),
].filter(Boolean).join(' · '))

const listText = computed({
	get: () => Array.isArray(model.value) ? model.value.join('\n') : String(model.value ?? ''),
	set: (value: string) => {
		model.value = value
	},
})

const textValue = computed({
	get: () => String(model.value ?? ''),
	set: (value: string) => {
		model.value = value
	},
})
</script>

<template>
	<div :class="[$style.field, { [$style.field_invalid]: error }]">
		<NcCheckboxRadioSwitch
			v-if="param.type === 'bool'"
			:modelValue="model === true"
			type="switch"
			:disabled="disabled"
			:description="param.help"
			@update:modelValue="model = $event">
			{{ param.label }}
		</NcCheckboxRadioSwitch>

		<template v-else>
			<DurationInput
				v-if="param.type === 'duration'"
				v-model="model as number | string"
				:label="param.label"
				:invalid="!!error"
				:disabled="disabled"
				:describedby="hintId" />

			<template v-else-if="param.type === 'choice'">
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<select
					:id="id"
					v-model="textValue"
					:class="$style.field__select"
					:disabled="disabled"
					:aria-describedby="hintId">
					<option v-for="choice in param.choices" :key="choice" :value="choice">
						{{ choiceLabel(choice) }}
					</option>
				</select>
			</template>

			<template v-else-if="param.type === 'text'">
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<textarea
					:id="id"
					v-model="textValue"
					:class="$style.field__text"
					rows="2"
					:disabled="disabled"
					:aria-invalid="error ? 'true' : undefined"
					:aria-describedby="hintId" />
			</template>

			<template v-else-if="param.type === 'string_list' || param.type === 'cidr_list'">
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<textarea
					:id="id"
					v-model="listText"
					:class="$style.field__list"
					rows="4"
					:disabled="disabled"
					:placeholder="param.type === 'cidr_list' ? '192.0.2.0/24' : ''"
					:aria-invalid="error ? 'true' : undefined"
					:aria-describedby="hintId" />
			</template>

			<template v-else>
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<span :class="$style.field__row">
					<input
						:id="id"
						v-model="textValue"
						:class="$style.field__number"
						type="text"
						:inputmode="param.type === 'float' ? 'decimal' : 'numeric'"
						autocomplete="off"
						:disabled="disabled"
						:aria-invalid="error ? 'true' : undefined"
						:aria-describedby="hintId">
					<span v-if="param.unit" :class="$style.field__unit">{{ param.unit }}</span>
				</span>
			</template>

			<p :id="hintId" :class="$style.field__hint">
				<span v-if="error" :class="$style.field__error">{{ error }}</span>
				<template v-else>
					<span v-if="param.help" :class="$style.field__help">{{ param.help }}</span>
					<span :class="$style.field__range">{{ hint }}<template v-if="param.type === 'string_list' || param.type === 'cidr_list'"> · {{ t(APP_ID, 'One entry per line') }}</template></span>
				</template>
			</p>
		</template>
	</div>
</template>

<style module>
.field {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	min-width: 0;
}

.field__label {
	font-weight: 600;
}

.field__row {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.field__number {
	width: 9em;
	margin: 0;
	font-variant-numeric: tabular-nums;
}

.field__unit {
	color: var(--color-text-maxcontrast);
}

.field__select {
	max-width: 300px;
	margin: 0;
}

.field__list {
	width: 100%;
	max-width: 420px;
	margin: 0;
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.field__text {
	width: 100%;
	max-width: 420px;
	margin: 0;
	resize: vertical;
}

.field__hint {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	line-height: 1.45;
}

.field__help {
	display: block;
	margin-bottom: 2px;
}

.field__range {
	display: block;
	font-variant-numeric: tabular-nums;
}

.field__error {
	color: var(--color-error-text);
	font-weight: 600;
}

.field_invalid .field__number,
.field_invalid .field__text,
.field_invalid .field__list {
	border-color: var(--color-border-error, var(--color-error)) !important;
}
</style>
