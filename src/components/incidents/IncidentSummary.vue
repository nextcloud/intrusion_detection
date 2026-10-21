<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentSummary } from '../../types.ts'

import { n, t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import TimeStamp from '../common/TimeStamp.vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'

const props = defineProps<{
	summary: IncidentSummary
}>()

const id = useId()

const facts = computed(() => [
	{ id: 'started', label: t(APP_ID, 'Started'), at: props.summary.startedAt },
	{ id: 'found', label: t(APP_ID, 'Found by Nextcloud'), at: props.summary.foundAt },
	{ id: 'last', label: t(APP_ID, 'Last activity'), at: props.summary.lastActivityAt },
])

const counts = computed(() => {
	const { entries, detections, enforced, observed } = props.summary.counts
	return [
		n(APP_ID, '{count} event', '{count} events', entries, { count: formatNumber(entries) }),
		n(APP_ID, '{count} detection', '{count} detections', detections, { count: formatNumber(detections) }),
		t(APP_ID, '{count} acted on', { count: formatNumber(enforced) }),
		t(APP_ID, '{count} only observed', { count: formatNumber(observed) }),
	].join(' · ')
})

const sections = computed(() => [
	{ id: 'happened', heading: t(APP_ID, 'What happened'), items: props.summary.happened, empty: t(APP_ID, 'Nothing was recorded in this period.') },
	{ id: 'measures', heading: t(APP_ID, 'What was done'), items: props.summary.measures, empty: t(APP_ID, 'Nothing was done.') },
	{ id: 'affected', heading: t(APP_ID, 'Who and what is involved'), items: props.summary.affected, empty: '–' },
	{ id: 'data', heading: t(APP_ID, 'Data that may be affected'), items: props.summary.dataCategories, empty: props.summary.dataNote ?? '–' },
])
</script>

<template>
	<section :class="$style.summary" :aria-labelledby="`${id}-heading`">
		<h4 :id="`${id}-heading`" class="hidden-visually">
			{{ t(APP_ID, 'Summary') }}
		</h4>
		<p :class="$style.summary__headline" data-test="incident-headline">
			{{ summary.headline }}
		</p>

		<dl :class="$style.summary__facts">
			<div v-for="fact in facts" :key="fact.id" :class="$style.summary__fact">
				<dt>{{ fact.label }}</dt>
				<dd>
					<TimeStamp v-if="fact.at !== null" :timestamp="fact.at" />
					<span v-else>–</span>
				</dd>
			</div>
		</dl>
		<p :class="$style.summary__counts" data-test="incident-counts">
			{{ counts }}
		</p>

		<NcNoteCard
			v-if="summary.openItems.length > 0"
			type="warning"
			:heading="t(APP_ID, 'Still open')"
			data-test="incident-open">
			<ul :class="$style.summary__list">
				<li v-for="(item, index) in summary.openItems" :key="index">
					{{ item }}
				</li>
			</ul>
		</NcNoteCard>

		<div :class="$style.summary__grid">
			<section
				v-for="section in sections"
				:key="section.id"
				:class="$style.summary__section"
				:aria-labelledby="`${id}-${section.id}`"
				:data-test="`incident-${section.id}`">
				<h5 :id="`${id}-${section.id}`" :class="$style.summary__heading">
					{{ section.heading }}
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
}

.summary__headline {
	margin: 0;
	max-width: 80ch;
	font-size: 1.1em;
	font-weight: 600;
	line-height: 1.5;
}

.summary__facts {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 8);
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
	font-weight: 600;
	font-variant-numeric: tabular-nums;
}

.summary__counts {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-variant-numeric: tabular-nums;
}

.summary__grid {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 260px), 1fr));
	gap: calc(var(--default-grid-baseline) * 5) calc(var(--default-grid-baseline) * 8);
	padding-block-start: calc(var(--default-grid-baseline) * 4);
	border-block-start: 1px solid var(--color-border);
}

.summary__section {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	min-width: 0;
}

.summary__heading {
	margin: 0;
	font-size: 0.95em;
	font-weight: 700;
}

.summary__list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
	line-height: 1.5;
	overflow-wrap: anywhere;
}

.summary__empty {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}
</style>
