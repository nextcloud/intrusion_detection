<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check } from '../../types.ts'

import { mdiAlertOutline, mdiChevronDown } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import CheckCard from './CheckCard.vue'
import ModeSwitch from './ModeSwitch.vue'
import { modeLabel, useCheckMode } from '../../composables/useCheckMode.ts'
import { advanced } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: Check
	/** Open "Customise", e.g. from a link */
	open?: boolean
}>()

const id = useId()
const customising = ref(false)
watch(() => props.open, (open) => {
	if (open) {
		customising.value = true
	}
}, { immediate: true })

const { mode, saving, missingRequirement, change } = useCheckMode(() => props.check)

/** How often the check fired in the last days, from the hourly totals */
const fired = computed(() => {
	const { detections, days } = props.check.stats
	return detections === 0
		? n(APP_ID, 'Quiet in the last %n day', 'Quiet in the last %n days', days)
		: n(APP_ID, 'Fired %n time in the last {days} days', 'Fired %n times in the last {days} days', detections, { days })
})

/** Why the check cannot run, or runs differently from its chosen mode; learning mode is said once, in the header */
const effectiveNote = computed(() => {
	const missing = missingRequirement.value
	if (missing !== null) {
		return ({
			memory_cache: t(APP_ID, 'Needs a memory cache'),
			mail: t(APP_ID, 'Needs email'),
		} as Record<string, string>)[missing.id] ?? missing.text
	}
	const { configured, effective, reason } = props.check.mode
	if (configured === effective || reason === 'learning') {
		return null
	}
	return reason === 'disabled'
		? t(APP_ID, 'Off: intrusion detection is turned off')
		: t(APP_ID, 'Runs as {mode}', { mode: modeLabel(effective) })
})
</script>

<template>
	<li
		:id="`check-${check.id}`"
		:class="[$style.row, { [$style.row_off]: check.mode.effective === 'off' }]"
		data-test="check-row">
		<div :class="$style.row__main">
			<div :class="$style.row__text">
				<h4 :id="`${id}-name`" :class="$style.row__name">
					{{ check.texts.name }}
				</h4>
				<p :class="$style.row__summary">
					{{ check.texts.summary }}
				</p>
				<p :class="$style.row__meta">
					<span :class="{ [$style.row__fired]: check.stats.detections > 0 }" data-test="check-fired">{{ fired }}</span>
					<span v-if="effectiveNote" :class="$style.row__note" :title="missingRequirement?.text">
						<NcIconSvgWrapper
							v-if="missingRequirement"
							inline
							:path="mdiAlertOutline"
							:size="16" />
						{{ effectiveNote }}
					</span>
				</p>
			</div>
			<div :class="$style.row__controls">
				<NcLoadingIcon v-if="saving" :size="20" :name="t(APP_ID, 'Saving')" />
				<ModeSwitch
					:modelValue="mode"
					:label="t(APP_ID, 'Mode of {check}', { check: check.texts.name })"
					:onlyOff="missingRequirement !== null"
					:disabled="saving"
					@update:modelValue="change" />
				<button
					v-if="advanced"
					type="button"
					:class="[$style.row__customise, { [$style.row__customise_open]: customising }]"
					:aria-expanded="customising ? 'true' : 'false'"
					:aria-controls="`${id}-card`"
					data-test="customise"
					@click="customising = !customising">
					<span>{{ t(APP_ID, 'Customise') }}</span>
					<NcIconSvgWrapper inline :path="mdiChevronDown" :size="20" />
				</button>
			</div>
		</div>
		<CheckCard v-if="advanced && customising" :id="`${id}-card`" :check="check" />
	</li>
</template>

<style module>
.row {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 4);
	border-bottom: 1px solid var(--color-border);
	scroll-margin-top: calc(var(--default-grid-baseline) * 4);
}

.row:last-child {
	border-bottom: none;
}

.row__main {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.row__text {
	flex: 1 1 320px;
	min-width: 0;
}

.row__name {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.row_off .row__name {
	color: var(--color-text-maxcontrast);
}

.row__summary {
	margin: calc(var(--default-grid-baseline) / 2) 0 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.45;
}

.row__meta {
	display: flex;
	flex-wrap: wrap;
	gap: 0 calc(var(--default-grid-baseline) * 3);
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.row__fired {
	color: var(--color-main-text);
	font-weight: 600;
}

.row__note {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	color: var(--color-warning-text);
	font-weight: 600;
}

.row__controls {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.row__controls button.row__customise {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	min-height: var(--default-clickable-area);
	margin: 0;
	padding-inline: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 2);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: 600;
	cursor: pointer;
}

.row__controls button.row__customise:hover {
	background-color: var(--color-background-hover);
}

.row__controls button.row__customise:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

.row__customise :last-child {
	transition: transform 180ms ease;
}

.row__customise_open :last-child {
	transform: rotate(180deg);
}

@media (prefers-reduced-motion: reduce) {
	.row__customise :last-child {
		transition: none;
	}
}
</style>
