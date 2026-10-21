<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { FailedLoginDay } from '../types.ts'

import { n, t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { calendarDay } from '../time.ts'

const props = defineProps<{
	/** One entry per day, oldest first */
	days: FailedLoginDay[]
}>()

const id = useId()
const active = ref<number | null>(null)

const max = computed(() => Math.max(1, ...props.days.map((day) => day.count)))
const bars = computed(() => props.days.map((day, index) => ({
	day,
	index,
	/** Days with failures are at least a little visible */
	height: day.count === 0 ? 0 : Math.max(8, Math.round((day.count / max.value) * 100)),
	label: calendarDay(day.day, 'long'),
	isToday: index === props.days.length - 1,
})))
const activeBar = computed(() => active.value === null ? null : bars.value[active.value] ?? null)

/**
 * Left and right arrow keys move between days.
 *
 * @param event - The key event
 */
function onKeydown(event: KeyboardEvent) {
	const last = props.days.length - 1
	const rtl = getComputedStyle(event.currentTarget as Element).direction === 'rtl'
	const step = { ArrowRight: rtl ? -1 : 1, ArrowLeft: rtl ? 1 : -1 }[event.key]
	if (step !== undefined) {
		event.preventDefault()
		active.value = Math.max(0, Math.min(last, (active.value ?? last) + step))
	} else if (event.key === 'Home' || event.key === 'End') {
		event.preventDefault()
		active.value = event.key === 'Home' ? 0 : last
	}
}
</script>

<template>
	<figure :class="$style.chart">
		<div
			:class="$style.chart__plot"
			role="img"
			tabindex="0"
			:aria-label="t(APP_ID, 'Failed logins per day. Use the arrow keys to read single days; the table below has all numbers.')"
			:aria-describedby="`${id}-table`"
			data-test="bars"
			@keydown="onKeydown"
			@focus="active = active ?? days.length - 1"
			@blur="active = null"
			@mouseleave="active = null">
			<span
				v-for="bar in bars"
				:key="bar.day.day"
				:class="[$style.slot, { [$style.slot_active]: active === bar.index }]"
				@mouseenter="active = bar.index">
				<span
					:class="[$style.bar, { [$style.bar_zero]: bar.day.count === 0, [$style.bar_today]: bar.isToday }]"
					:style="{ height: bar.height === 0 ? undefined : `${bar.height}%` }" />
			</span>
		</div>
		<div :class="$style.chart__axis" aria-hidden="true">
			<span>{{ days.length > 0 ? calendarDay(days[0].day, 'short') : '' }}</span>
			<span>{{ t(APP_ID, 'Today') }}</span>
		</div>
		<p :class="$style.chart__readout" aria-live="polite" data-test="bars-readout">
			<template v-if="activeBar">
				<strong>{{ activeBar.label }}</strong>
				{{ n(APP_ID, '%n failed login', '%n failed logins', activeBar.day.count) }}
			</template>
		</p>

		<table :id="`${id}-table`" class="hidden-visually">
			<caption>{{ t(APP_ID, 'Failed logins per day') }}</caption>
			<thead>
				<tr>
					<th scope="col">
						{{ t(APP_ID, 'Day') }}
					</th>
					<th scope="col">
						{{ t(APP_ID, 'Failed logins') }}
					</th>
				</tr>
			</thead>
			<tbody>
				<tr v-for="bar in bars" :key="bar.day.day">
					<th scope="row">
						{{ bar.label }}
					</th>
					<td>{{ formatNumber(bar.day.count) }}</td>
				</tr>
			</tbody>
		</table>
	</figure>
</template>

<style module>
.chart {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
}

.chart__plot {
	display: flex;
	align-items: flex-end;
	gap: 3px;
	height: 72px;
	padding-block-end: 1px;
	border-block-end: 1px solid var(--color-border);
	border-radius: var(--border-radius-element) var(--border-radius-element) 0 0;
}

.chart__plot:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 4px;
}

.slot {
	display: flex;
	flex: 1 1 0;
	align-items: flex-end;
	height: 100%;
	border-radius: 4px 4px 0 0;
}

.slot_active {
	background-color: var(--color-background-hover);
}

.bar {
	width: 100%;
	border-radius: 4px 4px 0 0;
	background-color: color-mix(in srgb, var(--color-primary-element) 70%, var(--color-main-background));
	transition: height 200ms ease;
}

.bar_today {
	background-color: var(--color-primary-element);
}

.bar_zero {
	height: 3px;
	border-radius: 2px;
	background-color: var(--color-border);
}

.chart__axis {
	display: flex;
	justify-content: space-between;
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.chart__readout {
	min-height: 1.5em;
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.chart__readout strong {
	margin-inline-end: calc(var(--default-grid-baseline) * 2);
	color: var(--color-main-text);
}

@media (prefers-reduced-motion: reduce) {
	.bar {
		transition: none;
	}
}
</style>
