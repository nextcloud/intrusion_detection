<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { IncidentSubject } from '../../utils/incidents.ts'

import { n, t } from '@nextcloud/l10n'
import { useId } from 'vue'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import OutcomeBadge from '../common/OutcomeBadge.vue'
import SeverityPill from '../common/SeverityPill.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	subjects: IncidentSubject[]
	/** The key of the subject whose report is shown */
	selected: string | null
	loading: boolean
	error: string | null
	/** More detections exist than were loaded */
	hasMore: boolean
}>()

const emit = defineEmits<{
	select: [subject: IncidentSubject]
}>()

const id = useId()

/**
 * @param subject - A listed subject
 */
function title(subject: IncidentSubject): string {
	return subject.type === 'address'
		? t(APP_ID, 'Address {address}', { address: subject.value })
		: t(APP_ID, 'Account {account}', { account: subject.value })
}

/**
 * The checks that fired, at most two by name.
 *
 * @param subject - A listed subject
 */
function checks(subject: IncidentSubject): string {
	const [first = '', second, ...more] = subject.checks
	if (second === undefined) {
		return first
	}
	return more.length === 0
		? t(APP_ID, '{first} and {second}', { first, second })
		: n(APP_ID, '{first}, {second} and %n more', '{first}, {second} and %n more', more.length, { first, second })
}
</script>

<template>
	<section :class="$style.list" :aria-labelledby="`${id}-heading`">
		<h4 :id="`${id}-heading`" :class="$style.list__heading">
			{{ t(APP_ID, 'Last 7 days') }}
		</h4>

		<NcNoteCard v-if="error" type="error" :text="error" />
		<div v-else-if="loading" :class="$style.list__skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 3" :key="i" height="60px" />
		</div>
		<p v-else-if="subjects.length === 0" :class="$style.list__empty" data-test="incident-list-empty">
			{{ t(APP_ID, 'No address or account was involved in a detection.') }}
		</p>

		<ul v-else :class="$style.list__items">
			<li v-for="subject in subjects" :key="subject.key">
				<button
					type="button"
					:class="[$style.item, { [$style.item_selected]: subject.key === selected }]"
					:aria-current="subject.key === selected ? 'true' : undefined"
					data-test="incident-subject-item"
					@click="emit('select', subject)">
					<span :class="$style.item__top">
						<span :class="$style.item__title">{{ title(subject) }}</span>
						<TimeStamp :class="$style.item__time" :timestamp="subject.updatedAt" short />
					</span>
					<span :class="$style.item__meta">
						<SeverityPill :severity="subject.severity" />
						<OutcomeBadge :outcome="subject.outcome" />
						<span :class="$style.item__checks">
							{{ n(APP_ID, '%n detection', '%n detections', subject.detections) }} · {{ checks(subject) }}
						</span>
					</span>
				</button>
			</li>
		</ul>

		<p v-if="hasMore && !loading" :class="$style.list__note">
			{{ t(APP_ID, 'Only the most recent detections are listed.') }}
		</p>
	</section>
</template>

<style module>
.list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.list__heading {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
	font-weight: 600;
}

.list__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.list__empty,
.list__note {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.list__note {
	font-size: 0.9em;
}

.list__items {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) / 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.list .item {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	width: 100%;
	min-height: auto;
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border: none;
	border-radius: var(--border-radius-large);
	background: transparent;
	color: var(--color-main-text);
	font-weight: normal;
	text-align: start;
	cursor: pointer;
}

.list .item:hover {
	background-color: var(--color-background-hover);
}

.list .item:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: -2px;
}

.list .item_selected,
.list .item_selected:hover {
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.item__top {
	display: flex;
	align-items: baseline;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.item__title {
	min-width: 0;
	font-weight: 600;
	overflow-wrap: anywhere;
}

.item__time {
	flex: 0 0 auto;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.item__meta {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 2);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.item__checks {
	min-width: 0;
	overflow-wrap: anywhere;
}
</style>
