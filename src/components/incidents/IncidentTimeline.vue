<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentEntry as Entry, IncidentReport } from '../../types.ts'

import { mdiTimelineClockOutline } from '@mdi/js'
import { getCanonicalLocale, n, t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import EmptyNote from '../common/EmptyNote.vue'
import IncidentEntry from './IncidentEntry.vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { kindIcon } from './kinds.ts'

const props = defineProps<{
	report: IncidentReport
}>()

/** Up to this many entries are shown expanded at first */
const EXPAND_UP_TO = 25

/** The kinds shown; empty for all */
const selected = ref<string[]>([])
const expanded = ref<Record<string, boolean>>({})

watch(() => props.report, (report) => {
	selected.value = []
	const open = report.entries.length <= EXPAND_UP_TO
	expanded.value = Object.fromEntries(report.entries.map((entry) => [entry.id, open]))
}, { immediate: true })

const kinds = computed(() => props.report.kinds.filter((kind) => kind.count > 0))
const labels = computed(() => Object.fromEntries(props.report.kinds.map((kind) => [kind.id, kind.label])))
const shown = computed(() => (selected.value.length === 0 ? props.report.entries : props.report.entries.filter((entry) => selected.value.includes(entry.kind))))
const allExpanded = computed(() => shown.value.length > 0 && shown.value.every((entry) => expanded.value[entry.id]))

const days = computed(() => {
	const format = new Intl.DateTimeFormat(getCanonicalLocale(), { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })
	const groups: { label: string, entries: Entry[] }[] = []
	for (const entry of shown.value) {
		const label = format.format(entry.at * 1000)
		const last = groups.at(-1)
		if (last && last.label === label) {
			last.entries.push(entry)
		} else {
			groups.push({ label, entries: [entry] })
		}
	}
	return groups
})

/**
 * Show or hide one kind of entries.
 *
 * @param kind - The kind
 */
function toggle(kind: string) {
	selected.value = selected.value.includes(kind) ? selected.value.filter((k) => k !== kind) : [...selected.value, kind]
}

/**
 * Expand or collapse every shown entry.
 */
function toggleAll() {
	const open = !allExpanded.value
	expanded.value = { ...expanded.value, ...Object.fromEntries(shown.value.map((entry) => [entry.id, open])) }
}
</script>

<template>
	<section :class="$style.timeline" aria-labelledby="ids-incident-timeline">
		<div :class="$style.timeline__head">
			<h4 id="ids-incident-timeline" :class="$style.timeline__heading">
				{{ t(APP_ID, 'Timeline') }}
			</h4>
			<NcButton v-if="shown.length > 0" variant="tertiary" @click="toggleAll">
				{{ allExpanded ? t(APP_ID, 'Collapse all') : t(APP_ID, 'Expand all') }}
			</NcButton>
		</div>

		<div
			v-if="kinds.length > 1"
			:class="$style.timeline__filters"
			role="group"
			:aria-label="t(APP_ID, 'Show only')">
			<button
				type="button"
				:class="[$style.chip, { [$style.chip_active]: selected.length === 0 }]"
				:aria-pressed="selected.length === 0 ? 'true' : 'false'"
				data-test="incident-filter-all"
				@click="selected = []">
				{{ t(APP_ID, 'All') }}
				<span :class="$style.chip__count">{{ formatNumber(report.entries.length) }}</span>
			</button>
			<button
				v-for="kind in kinds"
				:key="kind.id"
				type="button"
				:class="[$style.chip, { [$style.chip_active]: selected.includes(kind.id) }]"
				:aria-pressed="selected.includes(kind.id) ? 'true' : 'false'"
				:data-test="`incident-filter-${kind.id}`"
				@click="toggle(kind.id)">
				<NcIconSvgWrapper :path="kindIcon(kind.id)" :size="16" inline />
				{{ kind.label }}
				<span :class="$style.chip__count">{{ formatNumber(kind.count) }}</span>
			</button>
		</div>

		<p class="hidden-visually" aria-live="polite">
			{{ n(APP_ID, '%n entry shown', '%n entries shown', shown.length) }}
		</p>

		<EmptyNote
			v-if="report.entries.length === 0"
			:name="t(APP_ID, 'Nothing on the timeline')"
			:description="t(APP_ID, 'Nextcloud recorded nothing about this subject in this period. Try a longer period, or check the spelling.')"
			:icon="mdiTimelineClockOutline" />

		<template v-else>
			<div v-for="day in days" :key="day.label" :class="$style.timeline__day">
				<h5 :class="$style.timeline__date">
					{{ day.label }}
				</h5>
				<ol :class="$style.timeline__list">
					<IncidentEntry
						v-for="entry in day.entries"
						:key="entry.id"
						v-model:expanded="expanded[entry.id]"
						:entry="entry"
						:kindLabel="labels[entry.kind] ?? entry.kind" />
				</ol>
			</div>
		</template>
	</section>
</template>

<style module>
.timeline {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
}

.timeline__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.timeline__heading {
	margin: 0;
	font-size: 1.1em;
	font-weight: 700;
}

.timeline__filters {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.timeline__filters .chip {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1-5);
	min-height: 34px;
	margin: 0;
	padding-block: 0;
	padding-inline: var(--ids-space-3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--color-main-background);
	color: var(--color-main-text);
	font-weight: 600;
	cursor: pointer;
}

.timeline__filters .chip:hover {
	background-color: var(--color-background-hover);
}

.timeline__filters .chip:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: 2px;
}

.timeline__filters .chip_active,
.timeline__filters .chip_active:hover {
	border-color: var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.chip__count {
	min-width: 20px;
	padding-inline: var(--ids-space-1-5);
	border-radius: 10px;
	background-color: var(--color-background-dark);
	color: var(--color-main-text);
	font-size: 0.85em;
	line-height: 20px;
	text-align: center;
	font-variant-numeric: tabular-nums;
}

.timeline__day {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
}

.timeline__date {
	position: sticky;
	top: 0;
	z-index: 2;
	margin: 0;
	padding-block: var(--ids-space-1-5);
	background-color: var(--color-main-background);
	font-size: 0.95em;
	font-weight: 700;
}

.timeline__list {
	composes: plainList from '../../styles/shared.module.css';
	position: relative;
	display: flex;
	flex-direction: column;
}

/* The line that runs through the markers */
.timeline__list::before {
	content: '';
	position: absolute;
	inset-block: var(--ids-space-4);
	inset-inline-start: 17px;
	width: 2px;
	border-radius: 1px;
	background-color: var(--color-border);
}

@media (max-width: 600px) {
	.timeline__list::before {
		inset-inline-start: 13px;
	}
}
</style>
