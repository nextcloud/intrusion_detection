<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, Detection } from '../../types.ts'

import { mdiChevronDown } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId, watch } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SeverityPill from '../common/SeverityPill.vue'
import TimeStamp from '../common/TimeStamp.vue'
import DetectionRow from './DetectionRow.vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { commonSummary, groupSpan, highestSeverity } from '../../utils/groups.ts'

const props = defineProps<{
	/** Detections that read the same, newest first */
	detections: Detection[]
	/** A detection to open, e.g. from a link */
	openId?: number | null
}>()

const emit = defineEmits<{
	lift: [ban: Ban, reload: () => Promise<void>]
}>()

const id = useId()
const contains = (detectionId: number | null | undefined) => typeof detectionId === 'number' && props.detections.some((d) => d.id === detectionId)
const expanded = ref(contains(props.openId))
watch(() => props.openId, (openId) => {
	if (contains(openId)) {
		expanded.value = true
	}
})

const first = computed(() => props.detections[0]!)
const title = computed(() => t(APP_ID, '{count} × {check}', { count: formatNumber(props.detections.length), check: first.value.checkName }, undefined, { escape: false, sanitize: false }))
const summary = computed(() => commonSummary(props.detections))
</script>

<template>
	<li :class="[$style.group, { [$style.group_expanded]: expanded }]" data-test="detection-group">
		<button
			type="button"
			:class="$style.group__summary"
			:aria-expanded="expanded ? 'true' : 'false'"
			:aria-controls="`${id}-items`"
			@click="expanded = !expanded">
			<SeverityPill :severity="highestSeverity(detections)" />
			<span :class="$style.group__main">
				<span :class="$style.group__title">{{ title }}</span>
				<span :class="$style.group__facts">
					<span v-if="first.ip" :class="$style.group__address">{{ first.ip }}</span>
					<span v-if="first.uid">{{ t(APP_ID, 'account {account}', { account: first.uid }) }}</span>
					<span v-if="summary">{{ summary }}</span>
					<span>{{ groupSpan(detections) }}</span>
				</span>
			</span>
			<span :class="[$style.group__outcome, first.enforced ? $style.group__outcome_enforced : $style.group__outcome_observed]">
				{{ first.enforced ? t(APP_ID, 'Acted on') : t(APP_ID, 'Observed') }}
			</span>
			<TimeStamp :class="$style.group__time" :timestamp="first.lastSeenAt" short />
			<NcIconSvgWrapper
				inline
				:class="$style.group__chevron"
				:path="mdiChevronDown"
				:size="20" />
		</button>
		<ul v-if="expanded" :id="`${id}-items`" :class="$style.group__items">
			<DetectionRow
				v-for="detection in detections"
				:key="detection.id"
				:detection="detection"
				:open="openId === detection.id"
				@lift="(ban, reload) => emit('lift', ban, reload)" />
		</ul>
	</li>
</template>

<style module>
.group {
	border-bottom: 1px solid var(--color-border);
}

.group:last-child {
	border-bottom: none;
}

.group button.group__summary {
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

.group button.group__summary:hover {
	background-color: var(--color-background-hover);
}

.group button.group__summary:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.group__summary > :first-child {
	grid-area: severity;
	justify-self: start;
}

.group__main {
	grid-area: main;
	display: flex;
	flex-direction: column;
	min-width: 0;
}

.group__title {
	overflow: hidden;
	font-weight: 600;
	text-overflow: ellipsis;
	white-space: nowrap;
}

.group__facts {
	display: flex;
	flex-wrap: wrap;
	gap: 0 calc(var(--default-grid-baseline) * 3);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.group__address {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
}

.group__outcome {
	grid-area: outcome;
	justify-self: end;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-element);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 22px;
	white-space: nowrap;
}

.group__outcome_enforced {
	background-color: var(--color-primary-element);
	color: var(--color-primary-element-text);
}

.group__outcome_observed {
	border: 1px dashed var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text, var(--color-main-text));
}

.group__time {
	grid-area: time;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	white-space: nowrap;
}

.group .group__chevron {
	grid-area: chevron;
	color: var(--color-text-maxcontrast);
	transition: transform 180ms ease;
}

.group_expanded .group__chevron {
	transform: rotate(180deg);
}

.group__items {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	margin-inline-start: calc(var(--default-grid-baseline) * 6);
	padding: 0;
	border-inline-start: 2px solid var(--color-border);
	list-style: none;
}

@media (max-width: 600px) {
	.group button.group__summary {
		grid-template-columns: auto minmax(0, 1fr) auto;
		grid-template-areas:
			"severity time outcome"
			"main main main";
		gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 2);
	}

	.group .group__time {
		justify-self: start;
	}

	.group .group__chevron {
		display: none !important;
	}

	.group__items {
		margin-inline-start: calc(var(--default-grid-baseline) * 2);
	}
}

@media (prefers-reduced-motion: reduce) {
	.group .group__chevron {
		transition: none;
	}
}
</style>
