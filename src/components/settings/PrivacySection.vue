<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiCloudUploadOutline, mdiDatabaseOutline, mdiScaleBalance } from '@mdi/js'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import LiveSentence from '../checks/LiveSentence.vue'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import { state } from '../../store.ts'
import { usePrivacy } from '../../stores/settings.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const { data, error: loadError } = usePrivacy({ failure: () => t(APP_ID, 'The overview could not be loaded. Please reload the page.') })

/**
 * "Stored by" with at most three check names.
 *
 * @param checks - The names of the checks that store this data
 */
function storedBy(checks: string[]): string {
	const names = checks.length > 3
		? n(APP_ID, '{names} and %n more', '{names} and %n more', checks.length - 3, { names: checks.slice(0, 3).join(', ') })
		: checks.join(', ')
	return t(APP_ID, 'Stored by: {checks}', { checks: names })
}

const retentionSettings = computed(() => state.settings.filter((s) => s.group === 'privacy'))
const days = (name: string) => Number(state.settings.find((s) => s.name === name)?.value ?? 0)
const activeOutgoing = computed(() => data.value?.outgoing.filter((item) => item.active).map((item) => item.name) ?? [])
</script>

<template>
	<div :class="$style.stack">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock height="320px" />
			<SkeletonBlock height="140px" />
		</div>

		<template v-else>
			<SectionCard
				level="h4"
				:heading="t(APP_ID, 'What Nextcloud keeps')"
				:icon="mdiDatabaseOutline"
				data-test="privacy-kept">
				<p :class="$style.summary" data-test="privacy-retention">
					{{ n(APP_ID, 'Detections, logins and security changes are kept for %n day.', 'Detections, logins and security changes are kept for %n days.', days('retention_detections_days')) }}
					{{ t(APP_ID, 'Everything the checks keep is deleted automatically when its time is up.') }}
				</p>
				<SettingsGroup :settings="retentionSettings">
					<template #default="{ fill, changed }">
						<ShowMore
							:label="t(APP_ID, 'Show what is stored, why and for how long')"
							:note="n(APP_ID, '%n kind of data', '%n kinds of data', data.stored.length)"
							data-test="stored-toggle">
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
						</ShowMore>
					</template>
				</SettingsGroup>
			</SectionCard>

			<SectionCard level="h4" :heading="t(APP_ID, 'What leaves the server')" :icon="mdiCloudUploadOutline">
				<template #description>
					{{ t(APP_ID, 'Only what you switch on contacts another service, and this is everything it sends.') }}
				</template>
				<p :class="$style.summary" data-test="privacy-outgoing">
					<template v-if="activeOutgoing.length === 0">
						{{ t(APP_ID, 'Nothing is sent to other services.') }}
					</template>
					<template v-else>
						{{ t(APP_ID, 'Only these contact other services: {names}.', { names: activeOutgoing.join(', ') }) }}
					</template>
				</p>
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
			</SectionCard>

			<section :class="$style.gdpr" aria-labelledby="ids-gdpr-heading">
				<span :class="$style.gdpr__icon" aria-hidden="true">
					<NcIconSvgWrapper inline :path="mdiScaleBalance" :size="22" />
				</span>
				<div>
					<h4 id="ids-gdpr-heading" :class="$style.gdpr__heading">
						{{ t(APP_ID, 'A note on the GDPR') }}
					</h4>
					<p v-if="data.gdpr.length > 0" :class="$style.gdpr__text">
						{{ data.gdpr[0] }}
					</p>
					<ShowMore v-if="data.gdpr.length > 1" :label="t(APP_ID, 'Read more')">
						<p v-for="(paragraph, index) in data.gdpr.slice(1)" :key="index" :class="$style.gdpr__text">
							{{ paragraph }}
						</p>
					</ShowMore>
				</div>
			</section>
		</template>
	</div>
</template>

<style module>
.summary {
	margin: 0;
	max-width: 80ch;
	line-height: 1.6;
}

.stack {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
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
	padding: var(--ids-space-3);
	white-space: normal;
	overflow-wrap: anywhere;
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: top;
	line-height: 1.5;
}

.table thead th {
	padding-block: var(--ids-space-2);
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
	composes: muted from '../../styles/shared.module.css';
	display: block;
	margin-top: var(--ids-space-1);
	font-size: 0.85em;
	font-weight: normal;
}

.retention {
	overflow-wrap: normal;
}

.where {
	composes: muted from '../../styles/shared.module.css';
	display: block;
	overflow-wrap: normal;
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
}

.outgoing {
	composes: plainList from '../../styles/shared.module.css';
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 340px), 1fr));
	gap: var(--ids-space-3);
}

.outgoing__item {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1-5);
	padding: var(--ids-space-4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.outgoing__head {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
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
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.9em;
}

.gdpr {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-4);
	padding: var(--ids-space-5);
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
	margin: 0 0 var(--ids-space-2);
	font-size: 1.15em;
	font-weight: 700;
}

.gdpr__text {
	margin: 0 0 var(--ids-space-2);
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
		padding-block: var(--ids-space-3);
		border-bottom: 1px solid var(--color-border);
	}

	.table tbody tr:last-child {
		border-bottom: none;
	}

	.table th,
	.table td {
		padding: var(--ids-space-1) 0;
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
		padding: var(--ids-space-4);
	}
}
</style>
