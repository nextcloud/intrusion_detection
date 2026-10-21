<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { getCanonicalLocale, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'

const props = withDefaults(defineProps<{
	/** One value per day, oldest first */
	points: { day: string, value: number }[]
	/** What the values are, for the table screen readers get */
	label: string
	height?: number
}>(), {
	height: 32,
})

const WIDTH = 140
const GAP = 2

const max = computed(() => Math.max(1, ...props.points.map((p) => p.value)))
const bars = computed(() => {
	const count = Math.max(1, props.points.length)
	const width = (WIDTH - GAP * (count - 1)) / count
	return props.points.map((point, index) => {
		const height = point.value === 0 ? 2 : Math.max(3, (point.value / max.value) * (props.height - 2))
		return {
			...point,
			x: index * (width + GAP),
			y: props.height - height,
			width,
			height,
			title: t(APP_ID, '{day}: {count}', { day: dayLabel(point.day), count: formatNumber(point.value) }),
		}
	})
})

/**
 * @param day - A day as YYYY-MM-DD (UTC)
 */
function dayLabel(day: string): string {
	return new Date(day + 'T12:00:00Z').toLocaleDateString(getCanonicalLocale(), { day: 'numeric', month: 'short' })
}
</script>

<template>
	<span :class="$style.spark">
		<svg
			:class="$style.spark__svg"
			:viewBox="`0 0 ${WIDTH} ${height}`"
			:height="height"
			preserveAspectRatio="none"
			aria-hidden="true">
			<rect
				v-for="bar in bars"
				:key="bar.day"
				:class="[$style.spark__bar, { [$style.spark__bar_zero]: bar.value === 0 }]"
				:x="bar.x"
				:y="bar.y"
				:width="bar.width"
				:height="bar.height"
				rx="1.5">
				<title>{{ bar.title }}</title>
			</rect>
		</svg>
		<table class="hidden-visually">
			<caption>{{ label }}</caption>
			<tbody>
				<tr v-for="point in points" :key="point.day">
					<th scope="row">
						{{ dayLabel(point.day) }}
					</th>
					<td>{{ formatNumber(point.value) }}</td>
				</tr>
			</tbody>
		</table>
	</span>
</template>

<style module>
.spark {
	display: inline-block;
	width: 140px;
	max-width: 100%;
}

.spark__svg {
	display: block;
	width: 100%;
	overflow: visible;
}

.spark__bar {
	fill: var(--color-primary-element);
}

.spark__bar_zero {
	fill: var(--color-border-dark, var(--color-border));
}
</style>
