<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ban, DailyStats } from '../types.ts'

import { mdiShieldCheckOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, nextTick, onActivated, onMounted, ref, watch } from 'vue'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import LiftBanDialog from '../components/blocks/LiftBanDialog.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import DetectionChart from '../components/overview/DetectionChart.vue'
import DetectionList from '../components/overview/DetectionList.vue'
import LookupBox from '../components/overview/LookupBox.vue'
import ProblemList from '../components/ProblemList.vue'
import StatusBanner from '../components/StatusBanner.vue'
import { errorMessage, fetchDailyStats } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { advanced, openDetectionId, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const stats = ref<DailyStats | null>(null)
const statsError = ref<string | null>(null)
const liftTarget = ref<Ban | null>(null)
let afterLift: (() => Promise<void>) | null = null

/**
 * Only real problems need attention; tips are for those who look at the
 * advanced options. Nothing asks to be configured while the defaults fit.
 */
const problems = computed(() => (state.status?.problems ?? []).filter((problem) => advanced.value || problem.level !== 'info'))

const quiet = computed(() => stats.value !== null && stats.value.days.every((day) => day.enforced + day.observed === 0))

/**
 * Load the chart, which is shown with the advanced options.
 */
async function loadStats() {
	try {
		stats.value = await fetchDailyStats(30)
		statsError.value = null
	} catch (error) {
		logger.error('Could not load the daily statistics', { error })
		statsError.value = errorMessage(error, t(APP_ID, 'The chart could not be loaded.'))
	}
}

onMounted(() => {
	if (advanced.value) {
		loadStats()
	}
})
onActivated(() => {
	if (stats.value !== null) {
		loadStats()
	}
})
watch(advanced, (shown) => {
	if (shown && stats.value === null) {
		loadStats()
	}
})

/**
 * @param ban - The block to lift
 * @param reload - What to reload once it is lifted
 */
function onLift(ban: Ban, reload: () => Promise<void>) {
	liftTarget.value = ban
	afterLift = reload
}

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

		<ProblemList v-if="problems.length > 0" id="overview-attention" :problems="problems" />

		<section
			v-if="advanced"
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

		<div :class="$style.overview__main">
			<div :class="$style.card">
				<DetectionList @lift="onLift" />
			</div>

			<section :class="$style.card" aria-labelledby="ids-lookup-heading">
				<h3 id="ids-lookup-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'Look up an address or account') }}
				</h3>
				<LookupBox @openDetection="openDetection" @lift="onLift" />
			</section>
		</div>

		<LiftBanDialog :ban="liftTarget" @close="liftTarget = null" @lifted="afterLift?.()" />
	</div>
</template>

<style module>
.overview {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.overview__main {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__empty {
	margin-block: calc(var(--default-grid-baseline) * 6) !important;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
