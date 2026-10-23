<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban } from '../types.ts'

import { mdiShieldCheckOutline } from '@mdi/js'
import { computed, nextTick, ref, watch } from 'vue'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import LiftBanDialog from '../components/blocks/LiftBanDialog.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import AdminGrantRequests from '../components/confirmation/AdminGrantRequests.vue'
import PendingApprovals from '../components/confirmation/PendingApprovals.vue'
import DetectionChart from '../components/overview/DetectionChart.vue'
import DetectionList from '../components/overview/DetectionList.vue'
import LookupBox from '../components/overview/LookupBox.vue'
import ProblemList from '../components/ProblemList.vue'
import StatusBanner from '../components/StatusBanner.vue'
import { adminGrants, decidableLogins, openDetectionId, state } from '../store.ts'
import { useDailyStats } from '../stores/overview.ts'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'

const { data: stats, error: statsError } = useDailyStats({ failure: () => t(APP_ID, 'The chart could not be loaded.') })
const liftTarget = ref<Ban | null>(null)

/**
 * Only real problems need attention; tips are listed further down. Nothing
 * asks to be configured while the defaults fit.
 */
const problems = computed(() => (state.status?.problems ?? []).filter((problem) => problem.level !== 'info'))
const tips = computed(() => (state.status?.problems ?? []).filter((problem) => problem.level === 'info'))

const quiet = computed(() => stats.value !== null && stats.value.days.every((day) => day.enforced + day.observed === 0))

/**
 * Open a detection from the lookup.
 *
 * @param id - The detection id
 */
function openDetection(id: number) {
	openDetectionId.value = id
}

watch(openDetectionId, async (id) => {
	if (id !== null) {
		await nextTick()
		document.getElementById(`detection-${id}`)?.scrollIntoView({ block: 'center', behavior: 'smooth' })
	}
}, { immediate: true })
</script>

<template>
	<div :class="$style.overview">
		<StatusBanner v-if="state.status" :status="state.status" />

		<ProblemList
			v-if="problems.length > 0 || decidableLogins.length > 0 || adminGrants.length > 0"
			id="overview-attention"
			:problems="problems">
			<template v-if="decidableLogins.length > 0 || adminGrants.length > 0" #default>
				<AdminGrantRequests v-if="adminGrants.length > 0" :requests="adminGrants" />
				<PendingApprovals
					v-if="decidableLogins.length > 0"
					:approvals="decidableLogins"
					data-test="overview-waiting" />
			</template>
		</ProblemList>

		<div :class="$style.overview__main">
			<div :class="$style.card">
				<DetectionList @lift="liftTarget = $event" />
			</div>

			<section :class="$style.card" aria-labelledby="ids-lookup-heading">
				<h3 id="ids-lookup-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'Look up an address or account') }}
				</h3>
				<LookupBox @openDetection="openDetection" @lift="liftTarget = $event" />
			</section>
		</div>

		<ProblemList
			v-if="tips.length > 0"
			:heading="t(APP_ID, 'Tips')"
			:problems="tips"
			data-test="overview-tips" />

		<section
			:class="$style.card"
			aria-labelledby="ids-chart-heading"
			data-test="overview-chart">
			<h3 id="ids-chart-heading" :class="$style.card__heading">
				{{ t(APP_ID, 'Detections in the last 30 days') }}
			</h3>
			<NcNoteCard v-if="statsError" type="error" :text="statsError" />
			<div v-else-if="stats === null" :class="$style.card__skeleton" aria-busy="true">
				<SkeletonBlock width="40%" />
				<SkeletonBlock height="180px" />
			</div>
			<NcEmptyContent
				v-else-if="quiet"
				:class="$style.card__empty"
				:name="t(APP_ID, 'All quiet')"
				:description="t(APP_ID, 'No attacks in the last 30 days. Nextcloud is watching.')">
				<template #icon>
					<NcIconSvgWrapper :path="mdiShieldCheckOutline" />
				</template>
			</NcEmptyContent>
			<DetectionChart v-else :days="stats.days" />
		</section>

		<LiftBanDialog :ban="liftTarget" @close="liftTarget = null" />
	</div>
</template>

<style module>
.overview {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-5);
}

.overview__main {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-5);
}

.card {
	composes: card from '../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
	min-width: 0;
	padding: var(--ids-space-5);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.card__empty {
	margin-block: var(--ids-space-6) !important;
}

@media (max-width: 600px) {
	.card {
		padding: var(--ids-space-3);
	}
}
</style>
