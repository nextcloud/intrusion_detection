<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Param } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcTextArea from '@nextcloud/vue/components/NcTextArea'
import NcTextField from '@nextcloud/vue/components/NcTextField'
import SelectField from '../common/SelectField.vue'
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

/** Fields with a description of a few lines, switches with one, and lists take a whole row of a settings grid, so their text is not squeezed into a narrow column */
const wide = computed(() => (props.param.type === 'bool' && props.param.help !== '')
	|| props.param.help.length > 120
	|| props.param.type === 'string_list'
	|| props.param.type === 'cidr_list')

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
	t(APP_ID, 'default {value}', { value: typeof props.param.default === 'number' && props.param.type === 'int' ? formatNumber(props.param.default) : formatValue(props.param.default, props.param.type) }),
].filter(Boolean).join(' · '))

const listText = computed({
	get: () => Array.isArray(model.value) ? model.value.join('\n') : String(model.value ?? ''),
	set: (value: string) => {
		model.value = value
	},
})

const choices = computed(() => props.param.choices.map((choice) => ({ value: choice, label: choiceLabel(choice) })))

const textValue = computed({
	// Whole numbers are shown with digit groups, as in the hints and sentences
	get: () => typeof model.value === 'number' && props.param.type === 'int' ? formatNumber(model.value) : String(model.value ?? ''),
	set: (value: string) => {
		model.value = value
	},
})
</script>

<template>
	<div :class="[$style.field, { [$style.field_invalid]: error, [$style.field_wide]: wide }]" :data-wide="wide ? 'true' : undefined">
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

			<SelectField
				v-else-if="param.type === 'choice'"
				v-model="textValue"
				:class="$style.field__select"
				:label="param.label"
				:options="choices"
				:disabled="disabled"
				:aria-describedby="hintId" />

			<template v-else-if="param.type === 'string_list' || param.type === 'cidr_list'">
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<NcTextArea
					:id="id"
					v-model="listText"
					:class="$style.field__list"
					labelOutside
					rows="4"
					resize="vertical"
					:disabled="disabled"
					:placeholder="param.type === 'cidr_list' ? t(APP_ID, 'e.g. {example}', { example: '192.0.2.0/24' }) : ''"
					:error="!!error"
					:aria-describedby="hintId" />
			</template>

			<template v-else>
				<label :for="id" :class="$style.field__label">{{ param.label }}</label>
				<span :class="$style.field__row">
					<NcTextField
						:id="id"
						v-model="textValue"
						:class="$style.field__number"
						labelOutside
						:inputmode="param.type === 'float' ? 'decimal' : 'numeric'"
						autocomplete="off"
						:disabled="disabled"
						:error="!!error"
						:aria-describedby="hintId" />
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
	gap: var(--ids-space-1);
	min-width: 0;
}

.field_wide {
	grid-column: 1 / -1;
}

.field_wide > * {
	max-width: 80ch;
}

.field__label {
	font-weight: 600;
}

.field__row {
	display: flex;
	align-items: center;
	gap: var(--ids-space-2);
}

.field__number {
	flex: 0 1 12em;
	min-width: 0;
	font-variant-numeric: tabular-nums;
}

.field__unit {
	composes: muted from '../../styles/shared.module.css';
}

.field__select {
	width: 100%;
	max-width: 360px;
}

.field__list {
	max-width: 480px;
}

.field__list :global(textarea) {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.field__hint {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
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

</style>
