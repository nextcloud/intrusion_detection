<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Privacy } from '../types.ts'

import { mdiCloudUploadOutline, mdiDatabaseOutline, mdiScaleBalance } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onActivated, onMounted, ref } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import LiveSentence from '../components/checks/LiveSentence.vue'
import SectionCard from '../components/common/SectionCard.vue'
import SettingsGroup from '../components/common/SettingsGroup.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import StateBadge from '../components/common/StateBadge.vue'
import ContributionCard from '../components/privacy/ContributionCard.vue'
import { errorMessage, fetchPrivacy } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const data = ref<Privacy | null>(null)
const loadError = ref<string | null>(null)
const refreshing = ref(false)

/**
 * "Stored by" with at most three check names.
 *
 * @param checks - The names of the checks that store this data
 */
function storedBy(checks: string[]): string {
	const names = checks.length > 3
		? n(APP_ID, '{names} and %n more', '{names} and %n more', checks.length - 3, { names: checks.slice(0, 3).join(', ') }, { escape: false, sanitize: false })
		: checks.join(', ')
	return t(APP_ID, 'Stored by: {checks}', { checks: names }, undefined, { escape: false, sanitize: false })
}

const retentionSettings = computed(() => state.settings.filter((s) => s.group === 'privacy'))

/**
 * Load the overview.
 */
async function load() {
	refreshing.value = true
	try {
		data.value = await fetchPrivacy()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the data overview', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The overview could not be loaded. Please reload the page.'))
	} finally {
		refreshing.value = false
	}
}

onMounted(load)
onActivated(load)
</script>

<template>
	<div :class="$style.privacy">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock height="320px" />
			<SkeletonBlock height="140px" />
		</div>

		<template v-else>
			<SectionCard :heading="t(APP_ID, 'What Nextcloud stores')" :icon="mdiDatabaseOutline">
				<template #description>
					{{ t(APP_ID, 'Every kind of data the installed checks keep, why, and for how long. Everything is deleted automatically when its time is up.') }}
				</template>
				<SettingsGroup :settings="retentionSettings">
					<template #default="{ fill, changed }">
						<div :class="$style.tableWrap">
							<table :class="$style.table" data-test="stored-data">
								<colgroup>
									<col :class="$style.col_what">
									<col :class="$style.col_why">
									<col :class="$style.col_long">
									<col>
								</colgroup>
								<thead>
									<tr>
										<th scope="col">
											{{ t(APP_ID, 'What') }}
										</th>
										<th scope="col">
											{{ t(APP_ID, 'Why') }}
										</th>
										<th scope="col">
											{{ t(APP_ID, 'How long') }}
										</th>
										<th scope="col">
											{{ t(APP_ID, 'Where') }}
										</th>
									</tr>
								</thead>
								<tbody>
									<tr v-for="row in data.stored" :key="row.id">
										<th scope="row" :data-label="t(APP_ID, 'What')">
											<span :class="$style.name">{{ row.name }}</span>
											<span :class="$style.what">{{ row.what }}</span>
											<span v-if="row.checks.length > 0" :class="$style.users">
												{{ storedBy(row.checks) }}
											</span>
										</th>
										<td :data-label="t(APP_ID, 'Why')">
											{{ row.why }}
										</td>
										<td :data-label="t(APP_ID, 'How long')" :class="$style.retention">
											<LiveSentence :segments="fill(row.retention)" :changed="changed" />
										</td>
										<td :data-label="t(APP_ID, 'Where')">
											<code v-for="where in row.where.split(', ')" :key="where" :class="$style.where">{{ where }}</code>
										</td>
									</tr>
								</tbody>
							</table>
						</div>
					</template>
				</SettingsGroup>
			</SectionCard>

			<SectionCard :heading="t(APP_ID, 'What leaves the server')" :icon="mdiCloudUploadOutline">
				<template #description>
					{{ t(APP_ID, 'Only what you switch on contacts another service, and this is everything it sends.') }}
				</template>
				<ul :class="$style.outgoing">
					<li v-for="item in data.outgoing" :key="item.id" :class="$style.outgoing__item">
						<div :class="$style.outgoing__head">
							<h4 :class="$style.outgoing__name">
								{{ item.name }}
							</h4>
							<StateBadge :type="item.active ? 'success' : 'neutral'">
								{{ item.active ? t(APP_ID, 'On') : t(APP_ID, 'Off') }}
							</StateBadge>
						</div>
						<p :class="$style.outgoing__text">
							{{ item.text }}
						</p>
						<p v-if="item.items.length > 0" :class="$style.outgoing__items">
							{{ item.items.join(' · ') }}
						</p>
					</li>
				</ul>
				<ContributionCard
					v-if="data.contribution"
					:contribution="data.contribution"
					:refreshing="refreshing"
					@changed="data.contribution = $event"
					@refresh="load" />
			</SectionCard>

			<section :class="$style.gdpr" aria-labelledby="ids-gdpr-heading">
				<span :class="$style.gdpr__icon" aria-hidden="true">
					<NcIconSvgWrapper inline :path="mdiScaleBalance" :size="22" />
				</span>
				<div>
					<h3 id="ids-gdpr-heading" :class="$style.gdpr__heading">
						{{ t(APP_ID, 'A note on the GDPR') }}
					</h3>
					<p v-for="(paragraph, index) in data.gdpr" :key="index" :class="$style.gdpr__text">
						{{ paragraph }}
					</p>
				</div>
			</section>
		</template>
	</div>
</template>

<style module>
.privacy {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.tableWrap {
	overflow-x: auto;
}

.table {
	width: 100%;
	min-width: 720px;
	border-collapse: collapse;
	table-layout: fixed;
}

.table th,
.table td {
	padding: calc(var(--default-grid-baseline) * 3);
	white-space: normal;
	overflow-wrap: anywhere;
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: top;
	line-height: 1.5;
}

.table thead th {
	padding-block: calc(var(--default-grid-baseline) * 2);
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
	white-space: nowrap;
}

.table .col_what {
	width: 34%;
}

.table .col_why {
	width: 30%;
}

.table .col_long {
	width: 16%;
}

.table tbody th {
	font-weight: 600;
}

.table tbody td {
	color: var(--color-main-text);
}

.table tbody tr:last-child th,
.table tbody tr:last-child td {
	border-bottom: none;
}

.name {
	display: block;
	font-weight: 700;
}

.what {
	display: block;
	font-weight: normal;
}

.users {
	display: block;
	margin-top: calc(var(--default-grid-baseline) * 1);
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: normal;
}

.retention {
	overflow-wrap: normal;
}

.where {
	display: block;
	overflow-wrap: normal;
	color: var(--color-text-maxcontrast);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
}

.outgoing {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
	padding: 0;
	list-style: none;
}

.outgoing__item {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	padding: calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.outgoing__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 2);
}

.outgoing__name {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.outgoing__text,
.outgoing__items {
	margin: 0;
	line-height: 1.5;
}

.outgoing__items {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.gdpr {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 4);
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid color-mix(in srgb, var(--color-info) 30%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-info) 8%, var(--color-main-background));
}

.gdpr__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 40px;
	height: 40px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--color-info) 16%, var(--color-main-background));
	color: var(--color-info-text);
}

.gdpr__heading {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	font-size: 1.15em;
	font-weight: 700;
}

.gdpr__text {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	max-width: 85ch;
	line-height: 1.6;
}

.gdpr__text:last-child {
	margin-bottom: 0;
}

@media (max-width: 760px) {
	.table thead {
		display: none;
	}

	.table {
		min-width: 0;
	}

	.table colgroup {
		display: none;
	}

	.table,
	.table tbody,
	.table tr,
	.table th,
	.table td {
		display: block;
		width: 100% !important;
	}

	.table tr {
		padding-block: calc(var(--default-grid-baseline) * 3);
		border-bottom: 1px solid var(--color-border);
	}

	.table tbody tr:last-child {
		border-bottom: none;
	}

	.table th,
	.table td {
		padding: calc(var(--default-grid-baseline) * 1) 0;
		border: none !important;
	}

	.table td[data-label]::before {
		content: attr(data-label);
		display: block;
		color: var(--color-text-maxcontrast);
		font-size: 0.8em;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
	}

	.retention {
		white-space: normal;
	}

	.gdpr {
		flex-direction: column;
		padding: calc(var(--default-grid-baseline) * 4);
	}
}
</style>
