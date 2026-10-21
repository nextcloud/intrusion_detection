<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiChevronDown } from '@mdi/js'
import { useId } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'

/** Whether the content is shown; closed by default */
const open = defineModel<boolean>('open', { default: false })

defineProps<{
	/** The text of the toggle, e.g. "Show the example payload" */
	label: string
	/** A short note after the label, e.g. a count */
	note?: string
	/** "row" for a toggle that fills its container, as in a list of items */
	variant?: 'inline' | 'row'
}>()

defineSlots<{
	default?: () => unknown
	/** Replaces the label, e.g. for a label with markup */
	label?: () => unknown
}>()

const id = useId()
</script>

<template>
	<div :class="[$style.disclosure, $style[`disclosure_${variant ?? 'inline'}`], { [$style.disclosure_open]: open }]">
		<button
			type="button"
			:class="$style.disclosure__toggle"
			:aria-expanded="open ? 'true' : 'false'"
			:aria-controls="`${id}-content`"
			@click="open = !open">
			<span :class="$style.disclosure__label">
				<slot name="label">{{ label }}</slot>
			</span>
			<span v-if="note" :class="$style.disclosure__note">{{ note }}</span>
			<NcIconSvgWrapper
				inline
				:class="$style.disclosure__chevron"
				:path="mdiChevronDown"
				:size="20" />
		</button>
		<div :id="`${id}-content`" :class="$style.disclosure__collapse" :inert="!open">
			<div :class="$style.disclosure__content">
				<slot v-if="open" />
			</div>
		</div>
	</div>
</template>

<style module>
.disclosure {
	display: flex;
	flex-direction: column;
	min-width: 0;
}

.disclosure button.disclosure__toggle {
	display: inline-flex;
	align-items: center;
	align-self: flex-start;
	gap: calc(var(--default-grid-baseline) * 1.5);
	min-height: calc(var(--default-clickable-area) - var(--default-grid-baseline) * 2);
	margin: 0;
	margin-inline-start: calc(var(--default-grid-baseline) * -2);
	padding-block: 0;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: 600;
	text-align: start;
	cursor: pointer;
}

.disclosure_row button.disclosure__toggle {
	align-self: stretch;
	justify-content: space-between;
	min-height: var(--default-clickable-area);
	margin-inline-start: 0;
	padding-inline: calc(var(--default-grid-baseline) * 3);
}

.disclosure button.disclosure__toggle:hover {
	background-color: var(--color-background-hover);
}

.disclosure button.disclosure__toggle:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.disclosure__label {
	min-width: 0;
}

.disclosure_row .disclosure__label {
	flex: 1 1 auto;
}

.disclosure__note {
	color: var(--color-text-maxcontrast);
	font-weight: normal;
}

.disclosure__chevron {
	flex: 0 0 auto;
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.disclosure_open .disclosure__chevron {
	transform: rotate(180deg);
}

.disclosure__collapse {
	display: grid;
	grid-template-rows: 0fr;
	opacity: 0;
	transition: grid-template-rows 180ms ease, opacity 180ms ease;
}

.disclosure_open .disclosure__collapse {
	grid-template-rows: 1fr;
	opacity: 1;
}

.disclosure__content {
	min-height: 0;
	min-width: 0;
	overflow: hidden;
}

.disclosure_open .disclosure__content {
	padding-top: calc(var(--default-grid-baseline) * 2);
}

.disclosure_row.disclosure_open .disclosure__content {
	padding: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 3);
}

@media (prefers-reduced-motion: reduce) {
	.disclosure__chevron,
	.disclosure__collapse {
		transition: none;
	}
}
</style>
