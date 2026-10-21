<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '@nextcloud/l10n'
import { computed, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import SectionCard from '../../components/common/SectionCard.vue'
import ActivityRow from './ActivityRow.vue'
import LoadError from './LoadError.vue'
import { APP_ID } from '../../utils/format.ts'
import { dayLabel, groupByDay, hasNews } from '../activity.ts'
import { ACTIVITY_MAX, ACTIVITY_PAGE, loadActivity, personal } from '../store.ts'

const id = useId()
const activity = computed(() => personal.activity)
const days = computed(() => groupByDay(activity.value?.items ?? []))
const shown = computed(() => (activity.value !== null && hasNews(activity.value.items)) || (activity.value === null && personal.activityError !== null))
const canShowMore = computed(() => (activity.value?.hasMore ?? false) && personal.activityLimit < ACTIVITY_MAX)
</script>

<template>
	<SectionCard
		v-if="shown"
		:heading="t(APP_ID, 'Recent activity')"
		data-test="activity">
		<template #description>
			{{ t(APP_ID, 'Logins, changes to your account and what Nextcloud noticed in the last 30 days.') }}
		</template>

		<LoadError v-if="activity === null && personal.activityError" :text="personal.activityError" @retry="loadActivity()" />
		<template v-else-if="activity">
			<section
				v-for="(group, index) in days"
				:key="group.day"
				:class="$style.day"
				:aria-labelledby="`${id}-${index}`"
				:data-test="`day-${group.day}`">
				<h4 :id="`${id}-${index}`" :class="$style.day__heading">
					{{ dayLabel(group.day, activity.today) }}
				</h4>
				<ul :class="$style.day__list">
					<ActivityRow
						v-for="item in group.items"
						:key="item.id"
						:item="item"
						:timeZone="activity.timezone" />
				</ul>
			</section>
			<NcButton
				v-if="canShowMore"
				variant="tertiary"
				:class="$style.more"
				:disabled="personal.activityLoading"
				data-test="show-more"
				@click="loadActivity(personal.activityLimit + ACTIVITY_PAGE)">
				<template v-if="personal.activityLoading" #icon>
					<NcLoadingIcon :size="20" />
				</template>
				{{ t(APP_ID, 'Show more') }}
			</NcButton>
		</template>
	</SectionCard>
</template>

<style module>
.day {
	display: flex;
	flex-direction: column;
}

.day__heading {
	margin: 0;
	padding-block-end: var(--default-grid-baseline);
	border-block-end: 1px solid var(--color-border);
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
	font-weight: 600;
}

.day__list {
	margin: 0;
	padding: 0;
	list-style: none;
}

.more {
	align-self: flex-start;
}
</style>
