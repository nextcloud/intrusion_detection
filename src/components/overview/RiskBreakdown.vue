<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Risk } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	risk: Risk
}>()

/** The scale ends a little above the high tier, so a high score is not at the very edge */
const scaleMax = computed(() => Math.max(props.risk.tierHigh + 2, props.risk.score, 1))

/**
 * @param value - A score
 */
function position(value: number): string {
	return `${Math.min(100, Math.max(0, (value / scaleMax.value) * 100))}%`
}

/**
 * @param points - Points of one part
 */
function signed(points: number): string {
	return points > 0 ? `+${points}` : String(points)
}
</script>

<template>
	<section :class="$style.risk" data-test="risk-breakdown">
		<h5 :class="$style.risk__heading">
			{{ t(APP_ID, 'Risk score of the address') }}
		</h5>

		<div :class="$style.risk__summary">
			<span :class="[$style.risk__score, $style[`risk__score_${risk.tier}`]]">{{ risk.score }}</span>
			<div :class="$style.risk__scaleBox">
				<span :class="[$style.risk__tier, $style[`risk__tier_${risk.tier}`]]">
					<span :class="$style.risk__dot" aria-hidden="true" />
					{{ risk.tierLabel }}
				</span>
				<div
					v-if="risk.tierHigh > 0"
					:class="$style.risk__scale"
					role="img"
					:aria-label="t(APP_ID, 'Score {score}; elevated from {elevated}, high from {high}', { score: risk.score, elevated: risk.tierElevated, high: risk.tierHigh })">
					<span :class="$style.risk__band_elevated" :style="{ insetInlineStart: position(risk.tierElevated), width: `calc(${position(risk.tierHigh)} - ${position(risk.tierElevated)})` }" />
					<span :class="$style.risk__band_high" :style="{ insetInlineStart: position(risk.tierHigh) }" />
					<span :class="$style.risk__marker" :style="{ insetInlineStart: position(Math.max(0, risk.score)) }" />
				</div>
			</div>
		</div>

		<ul v-if="risk.parts.length > 0" :class="$style.risk__parts">
			<li v-for="part in risk.parts" :key="part.fact" :class="$style.risk__part">
				<span>{{ part.label }}</span>
				<span :class="[$style.risk__points, part.points < 0 ? $style.risk__points_minus : '']">{{ signed(part.points) }}</span>
			</li>
		</ul>
		<p v-else :class="$style.risk__muted">
			{{ t(APP_ID, 'Nothing suspicious was known about this address.') }}
		</p>

		<div v-if="risk.lowered.length > 0" :class="$style.risk__lowered">
			<p :class="$style.risk__muted">
				{{ t(APP_ID, 'Because of this score, lower limits applied to this address:') }}
			</p>
			<ul :class="$style.risk__limits">
				<li v-for="limit in risk.lowered" :key="limit.param">
					{{ limit.label }}:
					<strong>{{ limit.effective }}</strong>
					<span :class="[$style.risk__muted, $style.risk__instead]">
						{{ t(APP_ID, 'instead of {limit}', { limit: limit.plain }) }}
					</span>
				</li>
			</ul>
		</div>
	</section>
</template>

<style module>
.risk {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2.5);
	max-width: 520px;
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
}

.risk__heading {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.risk__summary {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 4);
}

.risk__score {
	--risk-color: var(--color-text-maxcontrast);
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 52px;
	height: 52px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--risk-color) 14%, var(--color-main-background));
	color: var(--risk-color);
	font-size: 1.5em;
	font-weight: 700;
	font-variant-numeric: tabular-nums;
}

.risk__score_elevated {
	--risk-color: var(--color-warning-text);
}

.risk__score_high {
	--risk-color: var(--color-error-text);
}

.risk__scaleBox {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.risk__tier {
	display: inline-flex;
	align-self: flex-start;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	padding-block: calc(var(--default-grid-baseline) / 2);
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
}

.risk__tier_elevated {
	background-color: color-mix(in srgb, var(--color-warning) 16%, var(--color-main-background));
	color: var(--color-warning-text);
}

.risk__tier_high {
	background-color: color-mix(in srgb, var(--color-error) 14%, var(--color-main-background));
	color: var(--color-error-text);
}

.risk__dot {
	width: 7px;
	height: 7px;
	border-radius: 50%;
	background-color: currentColor;
}

.risk__scale {
	position: relative;
	height: 10px;
	overflow: visible;
	border-radius: 5px;
	background-color: color-mix(in srgb, var(--color-success) 45%, var(--color-background-dark));
}

.risk__band_elevated,
.risk__band_high {
	position: absolute;
	inset-block: 0;
	border-inline-start: 2px solid var(--color-main-background);
}

.risk__band_elevated {
	background-color: color-mix(in srgb, var(--color-warning) 80%, var(--color-background-dark));
}

.risk__band_high {
	inset-inline-end: 0;
	border-start-end-radius: 5px;
	border-end-end-radius: 5px;
	background-color: color-mix(in srgb, var(--color-error) 80%, var(--color-background-dark));
}

.risk__marker {
	position: absolute;
	top: -3px;
	width: 4px;
	height: 16px;
	margin-inline-start: -2px;
	border-radius: 2px;
	background-color: var(--color-main-text);
	box-shadow: 0 0 0 2px var(--color-main-background);
}

.risk__parts,
.risk__limits {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	margin: 0;
	padding: 0;
	list-style: none;
}

.risk__part {
	display: flex;
	align-items: baseline;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block-end: calc(var(--default-grid-baseline) * 1.5);
	border-bottom: 1px solid var(--color-border);
	overflow-wrap: anywhere;
}

.risk__part:last-child {
	padding-block-end: 0;
	border-bottom: none;
}

.risk__points {
	flex: 0 0 auto;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-pill, 100px);
	background-color: color-mix(in srgb, var(--color-warning) 16%, var(--color-main-background));
	color: var(--color-warning-text);
	font-weight: 700;
	font-variant-numeric: tabular-nums;
}

.risk__points_minus {
	background-color: color-mix(in srgb, var(--color-success) 16%, var(--color-main-background));
	color: var(--color-success-text);
}

.risk__lowered {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
}

.risk__muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.risk__instead {
	margin-inline-start: 0.3em;
}
</style>
