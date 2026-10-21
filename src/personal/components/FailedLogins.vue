<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiChartBar, mdiShieldCheckOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import SectionCard from '../../components/common/SectionCard.vue'
import EmptyLine from './EmptyLine.vue'
import FailedLoginBars from './FailedLoginBars.vue'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { personal } from '../store.ts'

const stats = computed(() => personal.overview?.failedLogins ?? null)

const places = computed(() => {
	if (stats.value === null) {
		return ''
	}
	return stats.value.placesCapped
		? n(APP_ID, 'They came from at least %n different place.', 'They came from at least %n different places.', stats.value.places)
		: n(APP_ID, 'They came from %n place.', 'They came from %n different places.', stats.value.places)
})
</script>

<template>
	<SectionCard
		v-if="stats"
		:heading="t(APP_ID, 'Failed logins')"
		:icon="mdiChartBar"
		data-test="failed-logins">
		<template #description>
			{{ t(APP_ID, 'Logins to your account with a wrong password in the last 30 days.') }}
		</template>

		<EmptyLine
			v-if="stats.total === 0"
			:icon="mdiShieldCheckOutline"
			:text="t(APP_ID, 'No failed logins in the last 30 days.')" />
		<template v-else>
			<p :class="$style.summary" data-test="failed-summary">
				<strong :class="$style.summary__figure">{{ formatNumber(stats.total) }}</strong>
				<span>
					{{ n(APP_ID, 'failed login in the last 30 days.', 'failed logins in the last 30 days.', stats.total) }}
					{{ places }}
				</span>
			</p>
			<FailedLoginBars :days="stats.days" />
			<div v-if="stats.recent.length > 0" :class="$style.recent">
				<h4 :class="$style.recent__heading">
					{{ t(APP_ID, 'Most recent addresses') }}
				</h4>
				<ul :class="$style.recent__list" data-test="recent-addresses">
					<li v-for="source in stats.recent" :key="source.address" :class="$style.recent__item">
						<span :class="$style.recent__address">{{ source.address }}</span>
						<NcDateTime :timestamp="source.lastSeenAt * 1000" relativeTime="short" :format="{ dateStyle: 'long', timeStyle: 'short', timeZone: stats.timezone }" />
					</li>
				</ul>
			</div>
			<p :class="$style.advice">
				{{ t(APP_ID, 'A wrong password was not accepted. If you did not mistype it yourself, someone else tried to log in. A strong password and two-factor authentication keep them out.') }}
			</p>
		</template>
	</SectionCard>
</template>

<style module>
.summary {
	display: flex;
	flex-wrap: wrap;
	align-items: baseline;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	line-height: 1.5;
}

.summary__figure {
	font-size: 1.8em;
	font-weight: 700;
	line-height: 1;
	font-variant-numeric: tabular-nums;
}

.recent {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.recent__heading {
	margin: 0;
	font-size: 0.95em;
	font-weight: 600;
}

.recent__list {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.recent__item {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-block: calc(var(--default-grid-baseline) * 1);
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.recent__address {
	color: var(--color-main-text);
	font-family: var(--font-face-monospace, monospace);
	overflow-wrap: anywhere;
}

.advice {
	margin: 0;
	max-width: 75ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}
</style>
