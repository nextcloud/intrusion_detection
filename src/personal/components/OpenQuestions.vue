<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import SectionCard from '../../components/common/SectionCard.vue'
import EventItem from './EventItem.vue'
import { APP_ID } from '../../utils/format.ts'
import { isOpenQuestion } from '../activity.ts'
import { loadActivity, personal } from '../store.ts'

const questions = computed(() => (personal.activity?.questions ?? []).filter(isOpenQuestion))

/**
 * The answered question leaves at once; the timeline then has it with its answer.
 *
 * @param event - The event as the server returned it
 */
function answered(event: SecurityEvent) {
	if (personal.activity !== null) {
		personal.activity.questions = personal.activity.questions.filter((e) => e.id !== event.id)
	}
	loadActivity()
}
</script>

<template>
	<SectionCard
		v-if="questions.length > 0"
		:heading="t(APP_ID, 'Was this you?')"
		data-test="questions">
		<template #description>
			{{ t(APP_ID, 'Nextcloud noticed something it could not check by itself. Your answer decides what happens next.') }}
		</template>
		<ul :class="$style.list">
			<EventItem
				v-for="event in questions"
				:key="event.id"
				:event="event"
				@answered="answered"
				@stale="loadActivity()" />
		</ul>
	</SectionCard>
</template>

<style module>
.list {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
	padding: 0;
	list-style: none;
}
</style>
