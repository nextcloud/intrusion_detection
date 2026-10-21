<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiChevronDown, mdiMinus } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
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
// Open steps are expanded; finished ones fold away but can be opened again.
const expanded = ref(!props.done && !props.skipped)
watch(() => props.done, (done) => {
	if (done) {
		expanded.value = false
	}
})

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
				<NcIconSvgWrapper :class="$style.step__chevron" :path="mdiChevronDown" :size="20" />
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
	gap: calc(var(--default-grid-baseline) * 3);
	width: 100%;
	min-height: calc(var(--default-clickable-area) + var(--default-grid-baseline) * 4);
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
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
	outline: 2px solid var(--color-main-text);
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
	display: inline-flex;
	color: var(--color-text-maxcontrast);
}

.step__heading {
	margin: 0;
	font-size: 1.05em;
	font-weight: 600;
}

.step_skipped .step__heading {
	color: var(--color-text-maxcontrast);
}

.step__state {
	padding-inline: calc(var(--default-grid-baseline) * 2);
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
	gap: calc(var(--default-grid-baseline) * 3);
	padding: 0 calc(var(--default-grid-baseline) * 5) calc(var(--default-grid-baseline) * 5) calc(var(--default-grid-baseline) * 4 + 32px + var(--default-grid-baseline) * 3);
	animation: step-reveal 180ms ease;
}

.step__description {
	margin: 0;
	color: var(--color-text-maxcontrast);
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
		grid-template-columns: auto minmax(0, 1fr) auto;
		padding-inline: calc(var(--default-grid-baseline) * 3);
	}

	.step__icon,
	.step .step__chevron {
		display: none !important;
	}

	.step__body {
		padding-inline: calc(var(--default-grid-baseline) * 3);
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
