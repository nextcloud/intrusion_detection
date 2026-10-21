<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts" generic="T extends string | number">
import { computed, useId } from 'vue'
import NcSelect from '@nextcloud/vue/components/NcSelect'

export interface SelectOption<V> {
	value: V
	label: string
}

const model = defineModel<T>({ required: true })

const props = defineProps<{
	options: SelectOption<T>[]
	/** The label; shown above the field, or only to screen readers with `hideLabel` */
	label: string
	hideLabel?: boolean
	disabled?: boolean
}>()

const id = useId()

const selected = computed<SelectOption<T> | null>({
	get: () => props.options.find((option) => option.value === model.value) ?? null,
	set: (option) => {
		if (option !== null) {
			model.value = option.value
		}
	},
})
</script>

<template>
	<div :class="$style.select" data-test="select-field">
		<label v-if="!hideLabel" :for="id" :class="$style.select__label">{{ label }}</label>
		<NcSelect
			v-model="selected"
			:inputId="id"
			:options="options"
			labelOutside
			:ariaLabelCombobox="hideLabel ? label : undefined"
			:clearable="false"
			:searchable="options.length > 10"
			:disabled="disabled">
			<template #selected-option="option">
				<span :class="$style.select__selected" :title="option.label">{{ option.label }}</span>
			</template>
		</NcSelect>
	</div>
</template>

<style module>
.select {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	min-width: 0;
}

.select__label {
	font-weight: 600;
}

/* Fill the field, never wider than it. Stronger than NcSelect's own minimum
   width and margin, whichever stylesheet loads last. */
.select :global(.nc-select.v-select.select) {
	width: 100%;
	min-width: 0;
	margin: 0;
}

.select__selected {
	overflow: hidden;
	min-width: 0;
	text-overflow: ellipsis;
	white-space: nowrap;
}
</style>
