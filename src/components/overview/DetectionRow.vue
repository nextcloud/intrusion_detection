<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, Detection, DetectionDetail } from '../../types.ts'

import { mdiChevronDown } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SeverityPill from '../common/SeverityPill.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import TimeStamp from '../common/TimeStamp.vue'
import DetectionNarrative from './DetectionNarrative.vue'
import { errorMessage, fetchDetection } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	/** The row as listed; without it, the row loads itself from `detectionId` */
	detection?: Detection
	detectionId?: number
	open?: boolean
}>()

const emit = defineEmits<{
	lift: [ban: Ban, reload: () => Promise<void>]
}>()

const id = useId()
const expanded = ref(props.open ?? false)
const detail = ref<DetectionDetail | null>(null)
const error = ref<string | null>(null)
const loading = ref(false)

const rowId = computed(() => props.detection?.id ?? props.detectionId ?? 0)
const shown = computed(() => props.detection ?? detail.value?.detection ?? null)

/**
 * Load the narrative (again).
 */
async function load() {
	loading.value = true
	error.value = null
	try {
		detail.value = await fetchDetection(rowId.value)
	} catch (e) {
		logger.error('Could not load the detection', { error: e })
		error.value = errorMessage(e, t(APP_ID, 'The explanation could not be loaded. Please try again.'))
	} finally {
		loading.value = false
	}
}

watch(expanded, (open) => {
	if (open && detail.value === null && !loading.value) {
		load()
	}
}, { immediate: true })

watch(() => props.detection?.lastSeenAt, () => {
	detail.value = null
	if (expanded.value) {
		load()
	}
})
</script>

<template>
	<li :id="`detection-${rowId}`" :class="[$style.row, { [$style.row_expanded]: expanded }]">
		<div v-if="shown === null" :class="$style.row__summary" aria-busy="true">
			<SkeletonBlock width="60px" height="22px" />
			<SkeletonBlock width="40%" />
		</div>
		<button
			v-else
			type="button"
			:class="$style.row__summary"
			:aria-expanded="expanded ? 'true' : 'false'"
			:aria-controls="`${id}-detail`"
			@click="expanded = !expanded">
			<SeverityPill :severity="shown.severity" />
			<span :class="$style.row__main">
				<span :class="$style.row__title">{{ shown.checkName }}</span>
				<span :class="$style.row__facts">
					<span v-if="shown.ip" :class="$style.row__address">{{ shown.ip }}</span>
					<span v-if="shown.uid">{{ t(APP_ID, 'account {account}', { account: shown.uid }) }}</span>
					<span v-if="shown.summary">{{ shown.summary }}</span>
					<span v-if="shown.hits > 1">{{ n(APP_ID, '%n time', '%n times', shown.hits) }}</span>
				</span>
			</span>
			<span :class="[$style.row__outcome, shown.enforced ? $style.row__outcome_enforced : $style.row__outcome_observed]">
				{{ shown.enforced ? t(APP_ID, 'Acted on') : t(APP_ID, 'Observed') }}
			</span>
			<TimeStamp :class="$style.row__time" :timestamp="shown.lastSeenAt" short />
			<NcIconSvgWrapper
				inline
				:class="$style.row__chevron"
				:path="mdiChevronDown"
				:size="20" />
		</button>

		<div v-if="expanded" :id="`${id}-detail`" :class="$style.row__detail">
			<div v-if="loading && detail === null" :class="$style.row__skeleton">
				<SkeletonBlock width="40%" />
				<SkeletonBlock />
				<SkeletonBlock width="85%" />
				<SkeletonBlock width="60%" />
			</div>
			<NcNoteCard v-else-if="error" type="error" :text="error" />
			<DetectionNarrative v-else-if="detail" :detail="detail" @lift="(ban) => emit('lift', ban, load)" />
		</div>
	</li>
</template>

<style module>
.row {
	border-bottom: 1px solid var(--color-border);
}

.row:last-child {
	border-bottom: none;
}

.row .row__summary {
	display: grid;
	grid-template-columns: 6em minmax(0, 1fr) auto auto auto;
	grid-template-areas: "severity main outcome time chevron";
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	width: 100%;
	min-height: 56px;
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.row button.row__summary:hover {
	background-color: var(--color-background-hover);
}

.row button.row__summary:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.row__summary > :first-child {
	grid-area: severity;
	justify-self: start;
}

.row__main {
	grid-area: main;
	display: flex;
	flex-direction: column;
	min-width: 0;
}

.row__title {
	overflow: hidden;
	font-weight: 600;
	text-overflow: ellipsis;
	white-space: nowrap;
}

.row__facts {
	display: flex;
	flex-wrap: wrap;
	gap: 0 calc(var(--default-grid-baseline) * 3);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.row__address {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.row__outcome {
	grid-area: outcome;
	justify-self: end;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-element);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 22px;
	white-space: nowrap;
}

.row__outcome_enforced {
	background-color: var(--color-primary-element);
	color: var(--color-primary-element-text);
}

.row__outcome_observed {
	border: 1px dashed var(--color-primary-element);
	color: var(--color-primary-element-light-text, var(--color-main-text));
	background-color: var(--color-primary-element-light);
}

.row__time {
	grid-area: time;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	white-space: nowrap;
}

.row .row__chevron {
	grid-area: chevron;
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.row.row_expanded .row__chevron {
	transform: rotate(180deg);
}

.row__detail {
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 4) calc(var(--default-grid-baseline) * 5);
	animation: row-reveal 180ms ease;
}

.row__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

@keyframes row-reveal {
	from {
		opacity: 0;
		transform: translateY(-4px);
	}
}

@media (max-width: 600px) {
	.row .row__summary {
		grid-template-columns: auto minmax(0, 1fr) auto;
		grid-template-areas:
			"severity time outcome"
			"main main main";
		gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 2);
	}

	.row .row__time {
		justify-self: start;
	}

	.row .row__chevron {
		display: none !important;
	}

	.row__detail {
		padding-inline: calc(var(--default-grid-baseline) * 2);
	}
}

@media (prefers-reduced-motion: reduce) {
	.row .row__chevron {
		transition: none;
	}

	.row__detail {
		animation: none;
	}
}
</style>
