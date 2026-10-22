<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Blocklist } from '../../types.ts'

import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import ReferencePill from '../common/ReferencePill.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { APP_ID } from '../../utils/format.ts'

/** Where a list comes from and what its downloads brought */
const props = defineProps<{
	list: Blocklist
}>()

const isDeny = computed(() => props.list.purpose === 'deny')
const latestSample = computed(() => [...props.list.matches].sort((a, b) => b.day.localeCompare(a.day)).find((d) => d.sample.length > 0)?.sample ?? [])
</script>

<template>
	<dl :class="$style.details">
		<div>
			<dt>{{ t(APP_ID, 'Downloaded from') }}</dt>
			<dd><code :class="$style.url">{{ list.url }}</code></dd>
		</div>
		<div v-if="isDeny && list.reference">
			<dt>{{ t(APP_ID, 'Reference on the error page') }}</dt>
			<dd :class="$style.details__inline">
				<ReferencePill :reference="list.reference" />
				<span :class="$style.muted">{{ t(APP_ID, 'Visitors refused by this list see this reference, without the name of the list.') }}</span>
			</dd>
		</div>
		<div v-if="list.lastSuccessAt">
			<dt>{{ t(APP_ID, 'Last good version') }}</dt>
			<dd>
				<TimeStamp :timestamp="list.lastSuccessAt" />
				<span v-if="list.skipped > 0" :class="$style.muted">
					· {{ n(APP_ID, '%n line skipped as not an address range', '%n lines skipped as not address ranges', list.skipped) }}
				</span>
			</dd>
		</div>
		<div v-if="isDeny && latestSample.length > 0">
			<dt>{{ t(APP_ID, 'Last matched addresses') }}</dt>
			<dd :class="$style.sample">
				<code v-for="address in latestSample.slice(0, 8)" :key="address">{{ address }}</code>
				<span v-if="latestSample.length > 8" :class="$style.muted">{{ n(APP_ID, 'and %n more', 'and %n more', latestSample.length - 8) }}</span>
			</dd>
		</div>
	</dl>
</template>

<style module>
.details {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 280px), 1fr));
	gap: var(--ids-space-3) var(--ids-space-5);
	margin: 0;
}

.details dt {
	margin-bottom: var(--ids-space-1);
	color: var(--color-text-maxcontrast);
	font-size: 0.8em;
	font-weight: 700;
	letter-spacing: 0.06em;
	text-transform: uppercase;
}

.details dd {
	margin: 0;
}

.details__inline {
	display: flex;
	flex-direction: column;
	align-items: flex-start;
	gap: var(--ids-space-1);
}

.muted {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.9em;
}

.url {
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.9em;
	overflow-wrap: anywhere;
}

.sample {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-1-5);
}

.sample code {
	padding-inline: var(--ids-space-1-5);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-family: var(--font-face-monospace, ui-monospace, 'SFMono-Regular', Menlo, Consolas, monospace);
	font-size: 0.85em;
}
</style>
