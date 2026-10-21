<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { mdiAccountQuestionOutline, mdiHistory, mdiShieldCheckOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import SectionCard from '../../components/common/SectionCard.vue'
import StateBadge from '../../components/common/StateBadge.vue'
import EventItem from './EventItem.vue'
import LoadError from './LoadError.vue'
import SkeletonRows from './SkeletonRows.vue'
import { APP_ID } from '../../utils/format.ts'
import { fetchEvents } from '../api.ts'
import { useRemoteList } from '../useRemoteList.ts'

/** Shown before "Show all" */
const FIRST = 5

const { items: events, error, load } = useRemoteList<SecurityEvent>(
	() => fetchEvents(),
	() => t(APP_ID, 'Your security events could not be loaded. Please try again.'),
)
const showAll = ref(false)

const open = computed(() => (events.value ?? []).filter((event) => event.asks && event.verdict === null).length)
/** Open questions first, then the newest */
const sorted = computed(() => [...(events.value ?? [])].sort((a, b) => {
	const openA = a.asks && a.verdict === null ? 1 : 0
	const openB = b.asks && b.verdict === null ? 1 : 0
	return openB - openA || b.createdAt - a.createdAt
}))
const visible = computed(() => showAll.value ? sorted.value : sorted.value.slice(0, FIRST))

/**
 * Put the answered event in place of the old one.
 *
 * @param event - The event as the server returned it
 */
function replace(event: SecurityEvent) {
	if (events.value !== null) {
		events.value = events.value.map((e) => e.id === event.id ? event : e)
	}
}

onMounted(load)
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Security events')" :icon="mdiHistory" data-test="events">
		<template #description>
			{{ t(APP_ID, 'What happened, when and from where, and what Nextcloud did. Events stay here for you to read and answer.') }}
		</template>
		<template v-if="open > 0" #actions>
			<StateBadge type="warning" :icon="mdiAccountQuestionOutline" data-test="events-open">
				{{ n(APP_ID, '%n needs your answer', '%n need your answer', open) }}
			</StateBadge>
		</template>

		<LoadError v-if="error" :text="error" @retry="load" />
		<SkeletonRows v-else-if="events === null" :rows="2" />
		<NcEmptyContent
			v-else-if="events.length === 0"
			:class="$style.empty"
			:name="t(APP_ID, 'No security events')"
			:description="t(APP_ID, 'Nextcloud has not noticed anything unusual about your account. It keeps watching.')"
			data-test="events-empty">
			<template #icon>
				<NcIconSvgWrapper :path="mdiShieldCheckOutline" />
			</template>
		</NcEmptyContent>
		<template v-else>
			<ul :class="$style.list">
				<EventItem
					v-for="event in visible"
					:key="event.id"
					:event="event"
					@answered="replace"
					@stale="load" />
			</ul>
			<NcButton
				v-if="sorted.length > FIRST"
				variant="tertiary"
				:class="$style.more"
				:aria-expanded="showAll ? 'true' : 'false'"
				@click="showAll = !showAll">
				{{ showAll ? t(APP_ID, 'Show fewer events') : n(APP_ID, 'Show all %n events', 'Show all %n events', sorted.length) }}
			</NcButton>
		</template>
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

.empty {
	margin-block: calc(var(--default-grid-baseline) * 4) !important;
}

.more {
	align-self: flex-start;
}
</style>
