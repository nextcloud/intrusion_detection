<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiChevronDown, mdiMinus } from '@mdi/js'
import { computed, useId } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'

/** Whether the step is open; the checklist keeps one step open at a time */
const expanded = defineModel<boolean>('open', { default: false })

const props = defineProps<{
	/** The position among the steps that apply; skipped steps have none */
	number: number
	heading: string
	/** An outline icon path (mdi) for the step */
	icon: string
	done: boolean
	skipped?: boolean
}>()

defineSlots<{
	/** What the step is about, in one or two sentences */
	description?: () => unknown
	default?: () => unknown
}>()

const id = useId()

const state = computed(() => {
	if (props.skipped) {
		return t(APP_ID, 'Not available')
	}
	return props.done ? t(APP_ID, 'Done') : t(APP_ID, 'To do')
})
</script>

<template>
	<li :class="[$style.step, { [$style.step_done]: done, [$style.step_skipped]: skipped }]" :aria-labelledby="`${id}-heading`">
		<h3 :class="$style.step__title">
			<button
				type="button"
				:class="$style.step__head"
				:aria-expanded="expanded ? 'true' : 'false'"
				:aria-controls="`${id}-body`"
				@click="expanded = !expanded">
				<span :class="$style.step__marker" aria-hidden="true">
					<NcIconSvgWrapper v-if="done" :path="mdiCheck" :size="20" />
					<NcIconSvgWrapper v-else-if="skipped" :path="mdiMinus" :size="20" />
					<template v-else>{{ number }}</template>
				</span>
				<span :class="$style.step__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="icon" :size="20" />
				</span>
				<span :id="`${id}-heading`" :class="$style.step__heading">
					{{ heading }}
				</span>
				<span :class="[$style.step__state, done ? $style.step__state_done : (skipped ? $style.step__state_skipped : $style.step__state_open)]">
					{{ state }}
				</span>
				<NcIconSvgWrapper
					inline
					:class="$style.step__chevron"
					:path="mdiChevronDown"
					:size="20" />
			</button>
		</h3>
		<div v-show="expanded" :id="`${id}-body`" :class="$style.step__body">
			<p v-if="$slots.description" :class="$style.step__description">
				<slot name="description" />
			</p>
			<slot />
		</div>
	</li>
</template>

<style module>
.step {
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
	transition: border-color 150ms ease;
}

.step_done {
	border-color: color-mix(in srgb, var(--color-success) 35%, var(--color-border));
}

.step__title {
	margin: 0;
	font-size: inherit;
}

.step .step__head {
	display: grid;
	grid-template-columns: auto auto minmax(0, 1fr) auto auto;
	align-items: center;
	gap: var(--ids-space-3);
	width: 100%;
	min-height: calc(var(--default-clickable-area) + var(--ids-space-4));
	margin: 0;
	padding: var(--ids-space-3) var(--ids-space-4);
	border: none;
	border-radius: var(--border-radius-large);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.step .step__head:hover {
	background-color: var(--color-background-hover);
}

.step .step__head:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: -2px;
}

.step__marker {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 32px;
	height: 32px;
	border: 2px solid var(--color-border-maxcontrast, var(--color-border));
	border-radius: 50%;
	font-weight: 600;
	font-variant-numeric: tabular-nums;
}

.step_done .step__marker {
	border-color: var(--color-success-text);
	background-color: color-mix(in srgb, var(--color-success) 16%, var(--color-main-background));
	color: var(--color-success-text);
}

.step_skipped .step__marker {
	border-style: dashed;
	color: var(--color-text-maxcontrast);
}

.step__icon {
	composes: muted from '../../styles/shared.module.css';
	display: inline-flex;
}

.step__heading {
	min-width: 0;
	margin: 0;
	font-size: 1.05em;
	font-weight: 600;
	overflow-wrap: anywhere;
}

.step_skipped .step__heading {
	color: var(--color-text-maxcontrast);
}

.step__state {
	padding-inline: var(--ids-space-2);
	border-radius: var(--border-radius-element);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 24px;
	white-space: nowrap;
}

.step__state_done {
	background-color: color-mix(in srgb, var(--color-success) 14%, var(--color-main-background));
	color: var(--color-success-text);
}

.step__state_open {
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text, var(--color-main-text));
}

.step__state_skipped {
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.step__chevron {
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.step__head[aria-expanded='true'] .step__chevron {
	transform: rotate(180deg);
}

.step__body {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	padding: 0 var(--ids-space-5) var(--ids-space-5) calc(var(--ids-space-4) + 32px + var(--ids-space-3));
	animation: step-reveal 180ms ease;
}

.step__description {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
	line-height: 1.5;
}

@keyframes step-reveal {
	from {
		opacity: 0;
		transform: translateY(-4px);
	}
}

@media (max-width: 600px) {
	.step .step__head {
		grid-template-columns: auto minmax(0, 1fr) auto auto;
		gap: var(--ids-space-2);
		padding-inline: var(--ids-space-3);
	}

	.step__icon {
		display: none;
	}

	.step__body {
		padding-inline: var(--ids-space-3);
	}
}

@media (prefers-reduced-motion: reduce) {
	.step,
	.step .step__chevron {
		transition: none;
	}

	.step__body {
		animation: none;
	}
}
</style>
