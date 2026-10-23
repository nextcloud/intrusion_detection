<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Day } from '../../types.ts'

import { getCanonicalLocale } from '@nextcloud/l10n'
import { computed, onBeforeUnmount, onMounted, ref, useId } from 'vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	days: Day[]
}>()

const id = useId()
const active = ref<number | null>(null)
const plot = ref<HTMLElement | null>(null)
/** The plot is drawn at its real size, so text and bars are never stretched */
const width = ref(720)
let observer: ResizeObserver | undefined

onMounted(() => {
	if (plot.value) {
		width.value = Math.max(280, plot.value.clientWidth || 720)
		observer = new ResizeObserver(([entry]) => {
			if (entry && entry.contentRect.width > 0) {
				width.value = Math.max(280, entry.contentRect.width)
			}
		})
		observer.observe(plot.value)
	}
})
onBeforeUnmount(() => observer?.disconnect())

const HEIGHT = 220
const PAD_TOP = 12
const PAD_BOTTOM = 28
const PAD_START = 34
const PLOT_HEIGHT = HEIGHT - PAD_TOP - PAD_BOTTOM

/** A round maximum and three gridlines */
const scale = computed(() => {
	const max = Math.max(1, ...props.days.map((day) => day.enforced + day.observed))
	const step = niceStep(max / 3)
	const top = Math.max(step * 3, step * Math.ceil(max / step))
	const ticks: number[] = []
	for (let value = 0; value <= top; value += step) {
		ticks.push(value)
	}
	return { top, ticks }
})

const slot = computed(() => (width.value - PAD_START) / Math.max(1, props.days.length))
const barWidth = computed(() => Math.max(3, Math.min(22, slot.value * 0.62)))

const bars = computed(() => props.days.map((day, index) => {
	const total = day.enforced + day.observed
	const x = PAD_START + index * slot.value + (slot.value - barWidth.value) / 2
	const enforcedHeight = (day.enforced / scale.value.top) * PLOT_HEIGHT
	const observedHeight = (day.observed / scale.value.top) * PLOT_HEIGHT
	const base = PAD_TOP + PLOT_HEIGHT
	return {
		day,
		index,
		total,
		x,
		enforced: { y: base - enforcedHeight, height: enforcedHeight },
		observed: { y: base - enforcedHeight - observedHeight, height: observedHeight },
		// Labels every 7 days, counted back from today, so today is always labelled.
		label: (props.days.length - 1 - index) % 7 === 0 ? shortDate(day) : null,
	}
}))

const totals = computed(() => props.days.reduce((sum, day) => ({
	enforced: sum.enforced + day.enforced,
	observed: sum.observed + day.observed,
}), { enforced: 0, observed: 0 }))

const activeBar = computed(() => active.value === null ? null : bars.value[active.value] ?? null)

/** Keep the tooltip inside the plot near its edges */
const tooltipStyle = computed(() => {
	const bar = activeBar.value
	if (bar === null) {
		return {}
	}
	const center = bar.x + barWidth.value / 2
	const shift = center < 120 ? '0' : center > width.value - 120 ? '-100%' : '-50%'
	return { left: `${center}px`, transform: `translateX(${shift})` }
})

/**
 * @param raw - The step that would give exactly three gridlines
 */
function niceStep(raw: number): number {
	const power = 10 ** Math.floor(Math.log10(Math.max(raw, 1)))
	const fraction = raw / power
	const nice = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 5 ? 5 : 10
	return Math.max(1, nice * power)
}

/**
 * @param day - A day of the chart
 */
function shortDate(day: Day): string {
	return new Date(day.day + 'T12:00:00').toLocaleDateString(getCanonicalLocale(), { day: 'numeric', month: 'short' })
}

/**
 * @param day - A day of the chart
 */
function longDate(day: Day): string {
	return new Date(day.day + 'T12:00:00').toLocaleDateString(getCanonicalLocale(), { weekday: 'long', day: 'numeric', month: 'long' })
}

/**
 * A rectangle with rounded top corners, for the top segment of a bar.
 *
 * @param x - Left edge
 * @param y - Top edge
 * @param width - Width
 * @param height - Height
 */
function roundedTop(x: number, y: number, width: number, height: number): string {
	const r = Math.min(3, width / 2, height)
	return `M${x},${y + height} V${y + r} Q${x},${y} ${x + r},${y} H${x + width - r} Q${x + width},${y} ${x + width},${y + r} V${y + height} Z`
}

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
		<figcaption :class="$style.chart__caption">
			<span :class="$style.legend">
				<span :class="[$style.legend__swatch, $style.legend__swatch_enforced]" aria-hidden="true" />
				{{ t(APP_ID, 'Handled') }}
				<strong>{{ formatNumber(totals.enforced) }}</strong>
			</span>
			<span :class="$style.legend">
				<span :class="[$style.legend__swatch, $style.legend__swatch_observed]" aria-hidden="true" />
				{{ t(APP_ID, 'Only observed') }}
				<strong>{{ formatNumber(totals.observed) }}</strong>
			</span>
		</figcaption>

		<div ref="plot" :class="$style.chart__plot" dir="ltr">
			<svg
				:class="$style.chart__svg"
				:viewBox="`0 0 ${width} ${HEIGHT}`"
				:width="width"
				:height="HEIGHT"
				role="img"
				tabindex="0"
				:aria-label="t(APP_ID, 'Detections per day. Use the arrow keys to read single days; the table below has all numbers.')"
				:aria-describedby="`${id}-table`"
				@keydown="onKeydown"
				@focus="active = active ?? days.length - 1"
				@blur="active = null"
				@mouseleave="active = null">
				<defs>
					<pattern
						:id="`${id}-hatch`"
						width="5"
						height="5"
						patternUnits="userSpaceOnUse"
						patternTransform="rotate(45)">
						<rect width="5" height="5" :class="$style.hatch__background" />
						<line
							x1="0"
							y1="0"
							x2="0"
							y2="5"
							:class="$style.hatch__line" />
					</pattern>
				</defs>

				<g aria-hidden="true">
					<g v-for="tick in scale.ticks" :key="tick">
						<line
							:x1="PAD_START"
							:x2="width"
							:y1="PAD_TOP + PLOT_HEIGHT - (tick / scale.top) * PLOT_HEIGHT"
							:y2="PAD_TOP + PLOT_HEIGHT - (tick / scale.top) * PLOT_HEIGHT"
							:class="tick === 0 ? $style.axis : $style.grid" />
						<text
							:x="PAD_START - 8"
							:y="PAD_TOP + PLOT_HEIGHT - (tick / scale.top) * PLOT_HEIGHT + 4"
							text-anchor="end"
							:class="$style.label">{{ formatNumber(tick) }}</text>
					</g>

					<g v-for="bar in bars" :key="bar.day.day">
						<rect
							:x="PAD_START + bar.index * slot"
							:y="PAD_TOP"
							:width="slot"
							:height="PLOT_HEIGHT"
							:class="[$style.hit, { [$style.hit_active]: active === bar.index }]"
							@mouseenter="active = bar.index" />
						<path
							v-if="bar.enforced.height > 0"
							:d="bar.observed.height > 0 ? `M${bar.x},${bar.enforced.y} h${barWidth} v${bar.enforced.height} h${-barWidth} Z` : roundedTop(bar.x, bar.enforced.y, barWidth, bar.enforced.height)"
							:class="$style.bar_enforced"
							pointer-events="none" />
						<path
							v-if="bar.observed.height > 0"
							:d="roundedTop(bar.x, bar.observed.y, barWidth, bar.observed.height)"
							:fill="`url(#${id}-hatch)`"
							:class="$style.bar_observed"
							pointer-events="none" />
						<text
							v-if="bar.label"
							:x="bar.x + barWidth / 2"
							:y="HEIGHT - 8"
							text-anchor="middle"
							:class="$style.label">{{ bar.label }}</text>
					</g>
				</g>
			</svg>

			<div
				v-if="activeBar"
				:class="$style.tooltip"
				:style="tooltipStyle"
				aria-live="polite">
				<strong>{{ longDate(activeBar.day) }}</strong>
				<span>{{ n(APP_ID, '%n detection', '%n detections', activeBar.total) }}</span>
				<span v-if="activeBar.total > 0">{{ t(APP_ID, '{enforced} handled, {observed} only observed', { enforced: formatNumber(activeBar.day.enforced), observed: formatNumber(activeBar.day.observed) }) }}</span>
			</div>
		</div>

		<table :id="`${id}-table`" class="hidden-visually">
			<caption>{{ t(APP_ID, 'Detections per day') }}</caption>
			<thead>
				<tr>
					<th scope="col">
						{{ t(APP_ID, 'Day') }}
					</th>
					<th scope="col">
						{{ t(APP_ID, 'Handled') }}
					</th>
					<th scope="col">
						{{ t(APP_ID, 'Only observed') }}
					</th>
				</tr>
			</thead>
			<tbody>
				<tr v-for="day in days" :key="day.day">
					<th scope="row">
						{{ longDate(day) }}
					</th>
					<td>{{ day.enforced }}</td>
					<td>{{ day.observed }}</td>
				</tr>
			</tbody>
		</table>
	</figure>
</template>

<style module>
.chart {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
	margin: 0;
}

.chart__caption {
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-5);
}

.legend {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-2);
}

.legend strong {
	color: var(--color-main-text);
	font-variant-numeric: tabular-nums;
}

.legend__swatch {
	width: 14px;
	height: 14px;
	border-radius: 4px;
}

.legend__swatch_enforced {
	background-color: var(--color-primary-element);
}

.legend__swatch_observed {
	border: 1px solid var(--color-primary-element);
	background: repeating-linear-gradient(45deg, var(--color-primary-element-light) 0 3px, color-mix(in srgb, var(--color-primary-element) 55%, transparent) 3px 4px);
}

.chart__plot {
	position: relative;
}

.chart__svg {
	display: block;
	overflow: visible;
	border-radius: var(--border-radius-element);
}

.chart__svg:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: 4px;
}

.grid {
	stroke: var(--color-border);
	stroke-width: 1;
	stroke-dasharray: 3 4;
	vector-effect: non-scaling-stroke;
}

.axis {
	stroke: var(--color-border-dark, var(--color-border));
	stroke-width: 1;
	vector-effect: non-scaling-stroke;
}

.label {
	fill: var(--color-text-maxcontrast);
	font-size: 11px;
	font-variant-numeric: tabular-nums;
}

.hit {
	fill: transparent;
}

.hit_active {
	fill: var(--color-background-hover);
}

.bar_enforced {
	fill: var(--color-primary-element);
}

.bar_observed {
	stroke: var(--color-primary-element);
	stroke-width: 1;
	vector-effect: non-scaling-stroke;
}

.hatch__background {
	fill: var(--color-primary-element-light);
}

.hatch__line {
	stroke: var(--color-primary-element);
	stroke-width: 2;
	opacity: 0.55;
}

.tooltip {
	position: absolute;
	top: 0;
	display: flex;
	flex-direction: column;
	gap: 2px;
	padding: var(--ids-space-2) var(--ids-space-3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
	background-color: var(--color-main-background);
	box-shadow: 0 4px 16px color-mix(in srgb, var(--color-main-text) 14%, transparent);
	font-size: 0.9em;
	pointer-events: none;
	white-space: nowrap;
	z-index: 1;
}
</style>
