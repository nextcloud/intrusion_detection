<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationOverview } from '../../types.ts'

import { mdiAlertOutline, mdiCheckCircleOutline, mdiChevronDown, mdiDownload } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import TimeStamp from '../common/TimeStamp.vue'
import { useAction } from '../../composables/useAction.ts'
import { allUnconfirmableAccounts, useUnconfirmableAccounts } from '../../stores/settings.ts'
import { APP_ID, formatNumber } from '../../utils/format.ts'

const props = defineProps<{
	users: ConfirmationOverview['users']
	admins: ConfirmationOverview['admins']
}>()
/** The CSV holds at most this many accounts */
const CSV_MAX = 2000

const open = ref(false)
const adminsOnly = ref(false)
const failure = () => t(APP_ID, 'The accounts could not be loaded. Please try again.')
const { data: list, error, loading: loadingFirst, loadMore: nextPage } = useUnconfirmableAccounts(open, adminsOnly, { failure })
const accounts = computed(() => list.value?.accounts ?? [])
const exhausted = computed(() => list.value?.exhausted ?? false)
const { busy, run } = useAction()
const loading = computed(() => loadingFirst.value || busy.value === 'more')
const exporting = computed(() => busy.value === 'download')

watch(error, (message) => {
	if (message !== null) {
		showError(message)
	}
})

const share = computed(() => props.users.active === 0 ? 0 : props.users.withoutMethod / props.users.active)
const sharePercent = computed(() => new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 }).format(share.value))
const total = computed(() => adminsOnly.value ? props.admins.withNeither.length : props.users.withoutMethod)

/**
 * Load the next page of accounts.
 */
function loadMore() {
	run('more', nextPage, { fallback: failure() })
}

/**
 * @param value - A cell
 */
function csvCell(value: string): string {
	// A leading formula character would run in a spreadsheet.
	const safe = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value
	return `"${safe.replaceAll('"', '""')}"`
}

/**
 * Download every account as CSV, page by page.
 */
function download() {
	run('download', async () => {
		const rows = await allUnconfirmableAccounts(adminsOnly.value, CSV_MAX)
		const lines = [
			[t(APP_ID, 'Account'), t(APP_ID, 'Name'), t(APP_ID, 'Last login'), t(APP_ID, 'Groups')].map(csvCell).join(','),
			...rows.map((row) => [row.uid, row.displayName, row.lastLogin > 0 ? new Date(row.lastLogin * 1000).toISOString() : '', row.groups.join(' ')].map(csvCell).join(',')),
		]
		const link = document.createElement('a')
		link.href = URL.createObjectURL(new Blob([lines.join('\r\n')], { type: 'text/csv;charset=utf-8' }))
		link.download = `accounts-without-confirmation-${new Date().toISOString().slice(0, 10)}.csv`
		link.click()
		URL.revokeObjectURL(link.href)
	}, { fallback: t(APP_ID, 'The list could not be downloaded. Please try again.') })
}
</script>

<template>
	<div :class="$style.coverage">
		<div :class="$style.figures">
			<div :class="[$style.figure, { [$style.figure_warning]: share > 0.1 }]" data-test="users-without">
				<span :class="$style.figure__value">{{ formatNumber(users.withoutMethod) }}</span>
				<span :class="$style.figure__label">
					{{ n(APP_ID, 'of %n active account cannot confirm a login', 'of %n active accounts cannot confirm a login', users.active) }}
					<template v-if="users.active > 0">({{ sharePercent }})</template>
				</span>
			</div>
			<div :class="[$style.figure, { [$style.figure_error]: admins.withNeither.length > 0 }]" data-test="admins-without">
				<span :class="$style.figure__value">
					<NcIconSvgWrapper
						inline
						:path="admins.withNeither.length > 0 ? mdiAlertOutline : mdiCheckCircleOutline"
						:size="22" />
					{{ formatNumber(admins.withNeither.length) }}
				</span>
				<span :class="$style.figure__label">
					{{ n(APP_ID, 'of %n administrator cannot confirm a login', 'of %n administrators cannot confirm a login', admins.total) }}
				</span>
			</div>
		</div>

		<p :class="$style.text">
			{{ t(APP_ID, 'These accounts have neither a second factor nor an email address. If a check asks them to confirm a login, your choice under "When a risky login cannot be confirmed" decides what happens. Ask them to add an email address or set up a second factor.') }}
		</p>
		<p v-if="admins.withoutEmail > 0 || admins.withoutSecondFactor > 0" :class="$style.text">
			{{ t(APP_ID, 'Administrators: {email} without an email address, {secondFactor} without a second factor.', { email: formatNumber(admins.withoutEmail), secondFactor: formatNumber(admins.withoutSecondFactor) }) }}
		</p>

		<div v-if="users.withoutMethod > 0 || admins.withNeither.length > 0" :class="$style.actions">
			<NcButton :aria-expanded="open ? 'true' : 'false'" aria-controls="ids-unconfirmable-list" @click="open = !open">
				<template #icon>
					<NcIconSvgWrapper :path="mdiChevronDown" :class="[$style.chevron, { [$style.chevron_open]: open }]" />
				</template>
				{{ open ? t(APP_ID, 'Hide accounts') : t(APP_ID, 'Show accounts') }}
			</NcButton>
			<NcButton :disabled="exporting" @click="download">
				<template #icon>
					<NcLoadingIcon v-if="exporting" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiDownload" />
				</template>
				{{ t(APP_ID, 'Download as CSV') }}
			</NcButton>
		</div>

		<div v-if="open" id="ids-unconfirmable-list" :class="$style.listWrap">
			<NcCheckboxRadioSwitch v-model="adminsOnly" type="switch">
				{{ t(APP_ID, 'Only administrators') }}
			</NcCheckboxRadioSwitch>
			<table :class="$style.table" data-test="accounts">
				<thead>
					<tr>
						<th scope="col">
							{{ t(APP_ID, 'Account') }}
						</th>
						<th scope="col">
							{{ t(APP_ID, 'Last login') }}
						</th>
						<th scope="col">
							{{ t(APP_ID, 'Groups') }}
						</th>
					</tr>
				</thead>
				<tbody>
					<tr v-for="account in accounts" :key="account.uid">
						<th scope="row">
							<span :class="$style.name">{{ account.displayName }}</span>
							<span :class="$style.uid">{{ account.uid }}</span>
						</th>
						<td :data-label="t(APP_ID, 'Last login')">
							<TimeStamp v-if="account.lastLogin > 0" :timestamp="account.lastLogin" />
							<template v-else>
								{{ t(APP_ID, 'Never') }}
							</template>
						</td>
						<td :data-label="t(APP_ID, 'Groups')">
							{{ account.groups.join(', ') || '–' }}
						</td>
					</tr>
				</tbody>
			</table>
			<p v-if="!loading && accounts.length === 0" :class="$style.text">
				{{ t(APP_ID, 'No such accounts.') }}
			</p>
			<div :class="$style.actions">
				<NcButton v-if="!exhausted && accounts.length > 0" :disabled="loading" @click="loadMore">
					<template v-if="loading" #icon>
						<NcLoadingIcon :size="20" />
					</template>
					{{ t(APP_ID, 'Show more') }}
				</NcButton>
				<NcLoadingIcon v-else-if="loading" :size="20" />
				<span :class="$style.count">{{ t(APP_ID, '{shown} of {total} shown', { shown: formatNumber(accounts.length), total: formatNumber(total) }) }}</span>
			</div>
		</div>
	</div>
</template>

<style module>
.coverage {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.figures {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
}

.figure {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	padding: calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
}

.figure_warning {
	background-color: color-mix(in srgb, var(--color-warning) 12%, var(--color-main-background));
}

.figure_error {
	background-color: color-mix(in srgb, var(--color-error) 12%, var(--color-main-background));
}

.figure__value {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	font-size: 2em;
	font-weight: 700;
	line-height: 1.1;
}

.figure_error .figure__value {
	color: var(--color-error-text);
}

.figure__label {
	color: var(--color-text-maxcontrast);
}

.text {
	margin: 0;
	max-width: 85ch;
	line-height: 1.5;
}

.actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.chevron {
	transition: transform 150ms ease;
}

.chevron_open {
	transform: rotate(180deg);
}

@media (prefers-reduced-motion: reduce) {
	.chevron {
		transition: none;
	}
}

.listWrap {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.table {
	width: 100%;
	border-collapse: collapse;
}

.table th,
.table td {
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: top;
}

.table thead th {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
}

.name {
	display: block;
	font-weight: 700;
}

.uid,
.count {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

@media (max-width: 600px) {
	.table thead {
		display: none;
	}

	.table,
	.table tbody,
	.table tr,
	.table th,
	.table td {
		display: block;
	}

	.table tr {
		padding-block: calc(var(--default-grid-baseline) * 2);
		border-bottom: 1px solid var(--color-border);
	}

	.table th,
	.table td {
		padding: calc(var(--default-grid-baseline) * 0.5) 0;
		border: none;
	}

	.table td[data-label]::before {
		content: attr(data-label) ': ';
		color: var(--color-text-maxcontrast);
		font-size: 0.85em;
	}
}
</style>
