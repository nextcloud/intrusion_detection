<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, Detection } from '../../types.ts'

import { mdiChevronDown } from '@mdi/js'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import OutcomeBadge from '../common/OutcomeBadge.vue'
import SeverityPill from '../common/SeverityPill.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import TimeStamp from '../common/TimeStamp.vue'
import DetectionNarrative from './DetectionNarrative.vue'
import { useDetection } from '../../stores/overview.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	/** The row as listed; without it, the row loads itself from `detectionId` */
	detection?: Detection
	detectionId?: string
	open?: boolean
}>()

const emit = defineEmits<{
	lift: [ban: Ban]
}>()

const id = useId()
const expanded = ref(props.open ?? false)
const rowId = computed(() => props.detection?.id ?? props.detectionId ?? 0)
/** The narrative loads when the row is opened first, and stays */
const opened = ref(expanded.value)
watch(expanded, (open) => {
	opened.value ||= open
})
const { data: detail, error, loading } = useDetection(() => opened.value ? rowId.value : null, () => props.detection?.lastSeenAt, {
	failure: () => t(APP_ID, 'The explanation could not be loaded. Please try again.'),
})
const shown = computed(() => props.detection ?? detail.value?.detection ?? null)
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
				<span :class="$style.row__title" data-test="detection-summary">{{ shown.summary || shown.checkName }}</span>
				<span :class="$style.row__facts">
					<span v-if="shown.summary">{{ shown.checkName }}</span>
					<span v-if="shown.ip" :class="$style.row__address">{{ shown.ip }}</span>
					<span v-if="shown.uid">{{ t(APP_ID, 'account {account}', { account: shown.uid }) }}</span>
					<span v-if="shown.hits > 1">{{ n(APP_ID, '%n time', '%n times', shown.hits) }}</span>
				</span>
			</span>
			<OutcomeBadge :class="$style.row__outcome" :outcome="shown.outcome" />
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
			<DetectionNarrative v-else-if="detail" :detail="detail" @lift="emit('lift', $event)" />
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
	grid-template-columns: 6em minmax(0, 1fr) 7.5em 7em 20px;
	grid-template-areas: "severity main outcome time chevron";
	align-items: center;
	gap: var(--ids-space-3);
	width: 100%;
	min-height: 56px;
	margin: 0;
	padding: var(--ids-space-2) var(--ids-space-3);
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
	outline: var(--ids-focus-ring);
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
	font-weight: 600;
	overflow-wrap: anywhere;
}

.row__facts {
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: 0 var(--ids-space-3);
	font-size: 0.9em;
}

.row__address {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.row__outcome {
	grid-area: outcome;
	justify-self: end;
}

.row__time {
	grid-area: time;
	justify-self: end;
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
	padding: var(--ids-space-2) var(--ids-space-4) var(--ids-space-5);
	animation: row-reveal 180ms ease;
}

.row__skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

@keyframes row-reveal {
	from {
		opacity: 0;
		transform: translateY(-4px);
	}
}

@media (max-width: 600px) {
	.row .row__summary {
		grid-template-columns: auto minmax(0, 1fr) auto auto;
		grid-template-areas:
			"severity time outcome chevron"
			"main main main main";
		gap: var(--ids-space-1) var(--ids-space-2);
	}

	.row .row__time {
		justify-self: start;
	}

	.row__detail {
		padding-inline: var(--ids-space-2);
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
