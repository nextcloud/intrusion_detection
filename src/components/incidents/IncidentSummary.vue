<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentSummary } from '../../types.ts'

import { mdiAccountGroupOutline, mdiCheckCircleOutline, mdiDatabaseOutline, mdiFlagOutline, mdiTimelineClockOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import TimeStamp from '../common/TimeStamp.vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'

const props = defineProps<{
	summary: IncidentSummary
}>()

const facts = computed(() => [
	{ id: 'started', label: t(APP_ID, 'Started'), at: props.summary.startedAt },
	{ id: 'found', label: t(APP_ID, 'Found by Nextcloud'), at: props.summary.foundAt },
	{ id: 'last', label: t(APP_ID, 'Last activity'), at: props.summary.lastActivityAt },
])

const figures = computed(() => [
	{ id: 'entries', value: props.summary.counts.entries, label: n(APP_ID, 'event', 'events', props.summary.counts.entries) },
	{ id: 'detections', value: props.summary.counts.detections, label: n(APP_ID, 'detection', 'detections', props.summary.counts.detections) },
	{ id: 'enforced', value: props.summary.counts.enforced, label: t(APP_ID, 'acted on') },
	{ id: 'observed', value: props.summary.counts.observed, label: t(APP_ID, 'only observed') },
])

const sections = computed(() => [
	{ id: 'happened', icon: mdiTimelineClockOutline, heading: t(APP_ID, 'What happened'), items: props.summary.happened, empty: t(APP_ID, 'Nothing was recorded in this period.') },
	{ id: 'affected', icon: mdiAccountGroupOutline, heading: t(APP_ID, 'Who and what is involved'), items: props.summary.affected, empty: '–' },
	{ id: 'data', icon: mdiDatabaseOutline, heading: t(APP_ID, 'Data that may be affected'), items: props.summary.dataCategories, empty: props.summary.dataNote ?? '–' },
	{ id: 'measures', icon: mdiCheckCircleOutline, heading: t(APP_ID, 'What was done'), items: props.summary.measures, empty: t(APP_ID, 'Nothing was done.') },
	{ id: 'open', icon: mdiFlagOutline, heading: t(APP_ID, 'Still open'), items: props.summary.openItems, empty: t(APP_ID, 'Nothing.') },
])
</script>

<template>
	<section :class="$style.summary" aria-labelledby="ids-incident-summary">
		<h4 id="ids-incident-summary" :class="$style.summary__eyebrow">
			{{ t(APP_ID, 'Summary') }}
		</h4>
		<p :class="$style.summary__headline" data-test="incident-headline">
			{{ summary.headline }}
		</p>

		<div :class="$style.summary__figures">
			<dl :class="$style.summary__facts">
				<div v-for="fact in facts" :key="fact.id" :class="$style.summary__fact">
					<dt>{{ fact.label }}</dt>
					<dd>
						<TimeStamp v-if="fact.at !== null" :timestamp="fact.at" />
						<span v-else>–</span>
					</dd>
				</div>
			</dl>
			<ul :class="$style.summary__counts" :aria-label="t(APP_ID, 'Counts')">
				<li v-for="figure in figures" :key="figure.id" :class="$style.summary__count">
					<span :class="$style.summary__number">{{ formatNumber(figure.value) }}</span>
					<span :class="$style.summary__label">{{ figure.label }}</span>
				</li>
			</ul>
		</div>

		<div :class="$style.summary__grid">
			<section
				v-for="section in sections"
				:key="section.id"
				:class="[$style.summary__section, { [$style.summary__section_open]: section.id === 'open' && section.items.length > 0 }]"
				:data-test="`incident-${section.id}`">
				<h5 :class="$style.summary__heading">
					<NcIconSvgWrapper :path="section.icon" :size="18" />
					<span>{{ section.heading }}</span>
				</h5>
				<ul v-if="section.items.length > 0" :class="$style.summary__list">
					<li v-for="(item, index) in section.items" :key="index">
						{{ item }}
					</li>
				</ul>
				<p v-else :class="$style.summary__empty">
					{{ section.empty }}
				</p>
			</section>
		</div>
	</section>
</template>

<style module>
.summary {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-primary-element) 5%, var(--color-main-background));
}

.summary__eyebrow {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.summary__headline {
	margin: 0;
	max-width: 80ch;
	font-size: 1.15em;
	font-weight: 600;
	line-height: 1.5;
}

.summary__figures {
	display: flex;
	flex-wrap: wrap;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 4) calc(var(--default-grid-baseline) * 8);
}

.summary__facts {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 8);
	margin: 0;
}

.summary__fact {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) / 2);
}

.summary__fact dt,
.summary__fact dd {
	height: auto;
	margin: 0;
	padding: 0;
	line-height: 1.4;
	text-align: start;
}

.summary__fact dt {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.summary__fact dd {
	margin: 0;
	font-weight: 600;
	font-variant-numeric: tabular-nums;
}

.summary__counts {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 6);
	margin: 0;
	padding: 0;
	list-style: none;
}

.summary__count {
	display: flex;
	flex-direction: column;
	align-items: flex-start;
}

.summary__number {
	font-size: 1.8em;
	font-weight: 700;
	line-height: 1.1;
	font-variant-numeric: tabular-nums;
}

.summary__label {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.summary__grid {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
}

.summary__section {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.summary__section_open {
	border-color: color-mix(in srgb, var(--color-warning) 55%, var(--color-border));
	background-color: color-mix(in srgb, var(--color-warning) 8%, var(--color-main-background));
}

.summary__heading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	font-size: 0.95em;
	font-weight: 700;
}

.summary__heading :global(.icon-vue) {
	color: var(--color-text-maxcontrast);
}

.summary__list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.5;
}

.summary__empty {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

@media (max-width: 600px) {
	.summary {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
