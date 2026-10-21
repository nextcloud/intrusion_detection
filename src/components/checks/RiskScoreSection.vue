<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCheck, mdiClose, mdiGauge } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import StateBadge from '../common/StateBadge.vue'
import LiveSentence from './LiveSentence.vue'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

/** The settings of the point table, in the order of the concept's table */
const POINTS = [
	'risk_points_attack_tool',
	'risk_points_tor',
	'risk_points_hosting',
	'risk_points_blocklist',
	'risk_points_trap',
	'risk_points_flagged',
	'risk_points_failures',
	'risk_points_office',
]

const settings = computed(() => state.settings.filter((s) => s.group === 'risk'))
const enabled = computed(() => state.settings.find((s) => s.name === 'risk_enabled')?.value !== false)
const points = computed(() => POINTS
	.map((name) => settings.value.find((s) => s.name === name))
	.filter((s) => s !== undefined))
const tiers = computed(() => [
	{ id: 'normal', name: t(APP_ID, 'Normal'), template: state.templates.riskNormal ?? '' },
	{ id: 'elevated', name: t(APP_ID, 'Elevated'), template: state.templates.riskElevated ?? '' },
	{ id: 'high', name: t(APP_ID, 'High'), template: state.templates.riskHigh ?? '' },
])
</script>

<template>
	<SectionCard
		v-if="settings.length > 0"
		:heading="t(APP_ID, 'Address risk score')"
		:icon="mdiGauge"
		data-test="risk-score">
		<template #description>
			{{ t(APP_ID, 'Some addresses are more suspicious than others. Nextcloud adds points for what it already knows about an address, and uses the score wherever it decides about one: a suspicious address meets lower limits, and a very suspicious one must confirm every password login. Nothing is looked up for it on normal requests.') }}
		</template>
		<template #actions>
			<StateBadge :type="enabled ? 'success' : 'warning'" :icon="enabled ? mdiCheck : mdiClose">
				{{ enabled ? t(APP_ID, 'On') : t(APP_ID, 'Off') }}
			</StateBadge>
		</template>

		<SettingsGroup :settings="settings" :collapsedLabel="t(APP_ID, 'Change the points and limits')">
			<template #default="{ fill, changed }">
				<div :class="$style.risk">
					<table :class="$style.table">
						<caption :class="$style.table__caption">
							{{ t(APP_ID, 'Points per fact') }}
						</caption>
						<thead class="hidden-visually">
							<tr>
								<th scope="col">
									{{ t(APP_ID, 'Fact') }}
								</th>
								<th scope="col">
									{{ t(APP_ID, 'Points') }}
								</th>
							</tr>
						</thead>
						<tbody>
							<tr v-for="setting in points" :key="setting.name">
								<th scope="row">
									{{ setting.label }}
								</th>
								<td :class="$style.table__points">
									<LiveSentence :segments="fill(`{${setting.name}}`)" :changed="changed" />
								</td>
							</tr>
						</tbody>
					</table>

					<div :class="$style.tiers">
						<h4 :class="$style.tiers__heading">
							{{ t(APP_ID, 'What the score changes') }}
						</h4>
						<ol :class="$style.tiers__list">
							<li v-for="tier in tiers" :key="tier.id" :class="[$style.tier, $style[`tier_${tier.id}`]]">
								<span :class="$style.tier__name">
									<span :class="$style.tier__dot" aria-hidden="true" />
									{{ tier.name }}
								</span>
								<span :class="$style.tier__text">
									<LiveSentence :segments="fill(tier.template)" :changed="changed" />
								</span>
							</li>
						</ol>
						<p :class="$style.tiers__note">
							{{ t(APP_ID, 'Lower limits apply to credential stuffing, password spraying, one account attacked from many places, share link attacks and password reset abuse. A high score is a reason for extra confirmation like the others; the login confirmation settings say what happens when an account has no way to confirm. Every detection shows the score of its address and how it came about.') }}
						</p>
					</div>
				</div>
			</template>
		</SettingsGroup>
	</SectionCard>
</template>

<style module>
.risk {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
	gap: calc(var(--default-grid-baseline) * 6);
	align-items: start;
}

.risk > * {
	min-width: 0;
}

.table {
	width: 100%;
	border-collapse: collapse;
}

.table__caption {
	margin-bottom: calc(var(--default-grid-baseline) * 2);
	font-weight: 700;
	text-align: start;
}

.table th,
.table td {
	padding-block: calc(var(--default-grid-baseline) * 2);
	border-bottom: 1px solid var(--color-border);
	vertical-align: top;
}

.table tbody tr:last-child th,
.table tbody tr:last-child td {
	border-bottom: none;
}

.table th {
	padding-inline-end: calc(var(--default-grid-baseline) * 3);
	font-weight: normal;
	text-align: start;
}

.table__points {
	width: 1%;
	font-variant-numeric: tabular-nums;
	text-align: end;
	white-space: nowrap;
}

.tiers {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.tiers__heading {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.tiers__list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.tier {
	--tier-color: var(--color-text-maxcontrast);
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	padding: calc(var(--default-grid-baseline) * 3);
	border-inline-start: 4px solid var(--tier-color);
	border-radius: var(--border-radius-element, 8px);
	background-color: color-mix(in srgb, var(--tier-color) 8%, var(--color-main-background));
}

.tier_elevated {
	--tier-color: var(--color-warning-text);
}

.tier_high {
	--tier-color: var(--color-error-text);
}

.tier__name {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	color: var(--tier-color);
	font-weight: 700;
}

.tier__dot {
	width: 8px;
	height: 8px;
	border-radius: 50%;
	background-color: currentColor;
}

.tier__text {
	line-height: 1.55;
}

.tiers__note {
	margin: 0;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}
</style>
