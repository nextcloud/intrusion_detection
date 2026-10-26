<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed } from 'vue'
import SectionCard from '../../components/common/SectionCard.vue'
import DenialReceipt from './DenialReceipt.vue'
import EventItem from './EventItem.vue'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { isOpenQuestion } from '../activity.ts'
import { personal, reloadActivity } from '../store.ts'

const questions = computed(() => (personal.activity?.questions ?? []).filter(isOpenQuestion))

/**
 * @param id - The answered event
 */
function closeReceipt(id: string) {
	personal.receipts = personal.receipts.filter((receipt) => receipt.id !== id)
}
</script>

<template>
	<SectionCard
		v-if="questions.length > 0 || personal.receipts.length > 0"
		:heading="t(APP_ID, 'Was this you?')"
		data-test="questions">
		<template #description>
			{{ t(APP_ID, 'Nextcloud noticed something it could not check by itself. Your answer decides what happens next.') }}
		</template>
		<ul :class="$style.list">
			<DenialReceipt
				v-for="receipt in personal.receipts"
				:key="`receipt-${receipt.id}`"
				:receipt="receipt"
				@close="closeReceipt(receipt.id)" />
			<EventItem
				v-for="event in questions"
				:key="event.id"
				:event="event"
				@stale="reloadActivity()" />
		</ul>
	</SectionCard>
</template>

<style module>
.list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}
</style>
