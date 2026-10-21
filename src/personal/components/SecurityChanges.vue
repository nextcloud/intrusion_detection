<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityChange } from '../../secureAccountTypes.ts'

import { mdiShieldEditOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onMounted } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SectionCard from '../../components/common/SectionCard.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import EmptyLine from './EmptyLine.vue'
import LoadError from './LoadError.vue'
import SkeletonRows from './SkeletonRows.vue'
import { fetchSecurityChanges } from '../../services/secureAccount.ts'
import { APP_ID } from '../../utils/format.ts'
import { personal } from '../store.ts'
import { useRemoteList } from '../useRemoteList.ts'

/** At most this many changes are shown */
const LIMIT = 20

const { items: changes, error, load } = useRemoteList<SecurityChange>(
	() => fetchSecurityChanges(LIMIT),
	() => t(APP_ID, 'Your recent security changes could not be loaded. Please try again.'),
)
const timeZone = computed(() => personal.overview?.timezone)

/** Who made a change, by its `via` */
const BY: Record<string, () => string> = {
	self: () => t(APP_ID, 'by you'),
	admin: () => t(APP_ID, 'by an administrator'),
	occ: () => t(APP_ID, 'by an administrator on the server'),
	reset: () => t(APP_ID, 'through a password reset'),
	system: () => t(APP_ID, 'by Nextcloud'),
}

/**
 * Who made the change, in words.
 *
 * @param change - The change
 */
function by(change: SecurityChange): string | null {
	return BY[change.via]?.() ?? null
}

/**
 * The previous and new value, where the change has them.
 *
 * @param change - The change
 */
function values(change: SecurityChange): string | null {
	if (change.previous && change.new) {
		return t(APP_ID, 'from {previous} to {new}', { previous: change.previous, new: change.new }, { escape: false })
	}
	if (change.previous) {
		return t(APP_ID, 'from {previous}', { previous: change.previous }, { escape: false })
	}
	return change.new ?? change.detail
}

onMounted(load)
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Recent security changes')" :icon="mdiShieldEditOutline" data-test="security-changes">
		<template #description>
			{{ t(APP_ID, 'Changes to your email address, password, second factor and app passwords. If you do not recognise one, change your password.') }}
		</template>

		<LoadError v-if="error" :text="error" @retry="load" />
		<SkeletonRows v-else-if="changes === null" :rows="3" />
		<EmptyLine
			v-else-if="changes.length === 0"
			:icon="mdiShieldEditOutline"
			:text="t(APP_ID, 'No security changes recently.')" />
		<ul v-else :class="$style.list">
			<li
				v-for="change in changes"
				:key="change.id"
				:class="$style.change"
				:data-test="`change-${change.id}`">
				<span :class="$style.change__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="mdiShieldEditOutline" :size="20" />
				</span>
				<div :class="$style.change__main">
					<p :class="$style.change__label">
						{{ change.label }}
						<span v-if="values(change)" :class="$style.change__values">{{ values(change) }}</span>
					</p>
					<p :class="$style.change__meta">
						<TimeStamp :timestamp="change.createdAt" :timeZone="timeZone" />
						<template v-if="by(change)">
							· {{ by(change) }}
						</template>
						<template v-if="change.address">
							· {{ t(APP_ID, 'from {address}', { address: change.address }) }}
						</template>
					</p>
				</div>
			</li>
		</ul>
	</SectionCard>
</template>

<style module>
.list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	list-style: none;
}

.change {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 3);
	border-block-start: 1px solid var(--color-border);
}

.change:first-child {
	padding-block-start: 0;
	border-block-start: none;
}

.change__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.change__main {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.change__label {
	margin: 0;
	font-weight: 600;
	overflow-wrap: anywhere;
}

.change__values {
	margin-inline-start: var(--default-grid-baseline);
	font-weight: normal;
}

.change__meta {
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	line-height: 1.5;
}
</style>
