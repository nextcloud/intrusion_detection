<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Notifications } from '../../types.ts'

import { mdiCheck, mdiFormatListChecks, mdiMinus } from '@mdi/js'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SectionCard from '../common/SectionCard.vue'
import ShowMore from '../common/ShowMore.vue'
import StateBadge from '../common/StateBadge.vue'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

/** Which checks notify the administrators and the affected user */
const props = defineProps<{
	checks: Notifications['checks']
}>()

const notifying = computed(() => props.checks.filter((c) => c.admin).length)
</script>

<template>
	<SectionCard
		level="h4"
		:heading="t(APP_ID, 'Notifications per check')"
		:icon="mdiFormatListChecks"
		data-test="per-check">
		<template #description>
			{{ n(APP_ID, '%n check notifies the administrators.', '%n checks notify the administrators.', notifying) }}
			{{ t(APP_ID, 'Change this with the responses of each check.') }}
		</template>
		<ShowMore :label="t(APP_ID, 'Show each check')" data-test="per-check-toggle">
			<div :class="$style.tableWrap">
				<table :class="$style.table">
					<thead>
						<tr>
							<th scope="col">
								{{ t(APP_ID, 'Check') }}
							</th>
							<th scope="col">
								{{ t(APP_ID, 'Administrators') }}
							</th>
							<th scope="col">
								{{ t(APP_ID, 'Affected user') }}
							</th>
						</tr>
					</thead>
					<tbody>
						<tr v-for="check in checks" :key="check.id" :class="{ [$style.row_off]: check.mode === 'off' }">
							<th scope="row">
								<a :href="`#checks/${check.id}`" :class="$style.checkLink">{{ check.name }}</a>
								<StateBadge v-if="check.mode === 'off'">
									{{ t(APP_ID, 'Off') }}
								</StateBadge>
							</th>
							<td :data-label="t(APP_ID, 'Administrators')">
								<span v-if="!check.adminAvailable" :class="$style.muted" :title="t(APP_ID, 'This check has no such response')">
									<span aria-hidden="true">—</span>
									<span class="hidden-visually">{{ t(APP_ID, 'This check has no such response') }}</span>
								</span>
								<span v-else :class="check.admin ? $style.yes : $style.no">
									<NcIconSvgWrapper inline :path="check.admin ? mdiCheck : mdiMinus" :size="18" />
									{{ check.admin ? t(APP_ID, 'Notified') : t(APP_ID, 'Not notified') }}
								</span>
							</td>
							<td :data-label="t(APP_ID, 'Affected user')">
								<span v-if="!check.userAvailable" :class="$style.muted" :title="t(APP_ID, 'This check has no such response')">
									<span aria-hidden="true">—</span>
									<span class="hidden-visually">{{ t(APP_ID, 'This check has no such response') }}</span>
								</span>
								<span v-else :class="check.user ? $style.yes : $style.no">
									<NcIconSvgWrapper inline :path="check.user ? mdiCheck : mdiMinus" :size="18" />
									{{ check.user ? t(APP_ID, 'Notified') : t(APP_ID, 'Not notified') }}
								</span>
							</td>
						</tr>
					</tbody>
				</table>
			</div>
		</ShowMore>
	</SectionCard>
</template>

<style module>
.tableWrap {
	overflow-x: auto;
}

.table {
	width: 100%;
	border-collapse: collapse;
}

.table th,
.table td {
	padding: var(--ids-space-2) var(--ids-space-3);
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: middle;
}

.table thead th {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
	white-space: nowrap;
}

.table tbody th {
	font-weight: normal;
}

.table tbody th > * + * {
	margin-inline-start: var(--ids-space-2);
}

.table tbody tr:last-child th,
.table tbody tr:last-child td {
	border-bottom: none;
}

.table tbody tr:hover {
	background-color: var(--color-background-hover);
}

.muted {
	composes: muted from '../../styles/shared.module.css';
}

.row_off {
	composes: muted from '../../styles/shared.module.css';
}

.checkLink {
	color: var(--color-main-text);
	font-weight: 600;
	text-decoration: none;
}

.checkLink:hover,
.checkLink:focus-visible {
	text-decoration: underline;
	text-underline-offset: 3px;
}

.yes,
.no {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
}

.yes {
	color: var(--color-success-text);
	font-weight: 600;
}

.no {
	color: var(--color-text-maxcontrast);
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
		width: 100%;
	}

	.table tr {
		padding-block: var(--ids-space-2);
		border-bottom: 1px solid var(--color-border);
	}

	.table th,
	.table td {
		padding: var(--ids-space-1) 0;
		border: none;
	}

	.table td[data-label]::before {
		content: attr(data-label) ': ';
		color: var(--color-text-maxcontrast);
		font-size: 0.9em;
	}
}
</style>
