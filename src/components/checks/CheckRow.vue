<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Check } from '../../types.ts'

import { mdiAlertOutline, mdiChevronDown } from '@mdi/js'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import CheckCard from './CheckCard.vue'
import ModeSwitch from './ModeSwitch.vue'
import { useCheckMode } from '../../composables/useCheckMode.ts'
import { modeLabel } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

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
	const { configured, effective, reason, locked } = props.check.mode
	if (locked) {
		return t(APP_ID, 'Locked in config.php')
	}
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
					:disabled="saving || check.mode.locked"
					@update:modelValue="change" />
				<button
					type="button"
					:class="[$style.row__customise, { [$style.row__customise_open]: customising }]"
					:aria-expanded="customising ? 'true' : 'false'"
					:aria-controls="`${id}-card`"
					data-test="customise"
					@click="customising = !customising">
					<span>{{ t(APP_ID, 'Customise') }}</span>
					<NcIconSvgWrapper
						inline
						:class="$style.row__chevron"
						:path="mdiChevronDown"
						:size="20" />
				</button>
			</div>
		</div>
		<CheckCard v-if="customising" :id="`${id}-card`" :check="check" />
	</li>
</template>

<style module>
.row {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	padding-block: var(--ids-space-4);
	border-bottom: 1px solid var(--color-border);
	scroll-margin-top: var(--ids-space-4);
}

.row:last-child {
	border-bottom: none;
}

.row__main {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-3);
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
	composes: muted from '../../styles/shared.module.css';
	margin: var(--ids-space-half) 0 0;
	line-height: 1.45;
}

.row__meta {
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: 0 var(--ids-space-3);
	margin: var(--ids-space-1) 0 0;
	font-size: 0.9em;
}

.row__fired {
	color: var(--color-main-text);
	font-weight: 600;
}

.row__note {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	color: var(--color-warning-text);
	font-weight: 600;
}

.row__controls {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
}

.row__controls button.row__customise {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	min-height: var(--default-clickable-area);
	margin: 0;
	padding-inline: var(--ids-space-3) var(--ids-space-2);
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
	outline: var(--ids-focus-ring);
	outline-offset: 2px;
}

.row__chevron {
	transition: transform 180ms ease;
}

.row__customise_open .row__chevron {
	transform: rotate(180deg);
}

@media (prefers-reduced-motion: reduce) {
	.row__chevron {
		transition: none;
	}
}
</style>
