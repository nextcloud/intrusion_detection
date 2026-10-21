<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Lockdown, LockdownEntry } from '../../types.ts'

import { mdiLockAlertOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onMounted, ref, watch } from 'vue'
import NcDateTime from '@nextcloud/vue/components/NcDateTime'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import { errorMessage, fetchLockdown } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID, formatDuration } from '../../utils/format.ts'
import { actorLabel } from './summary.ts'

const lockdown = ref<Lockdown | null>(null)
const loadError = ref<string | null>(null)
const opts = { escape: false, sanitize: false }

/** The effects are chosen in the start dialog; the other settings are edited here */
const settings = computed(() => state.settings.filter((s) => s.group === 'lockdown' && s.name !== 'lockdown_effects'))

/**
 * Load the history.
 */
async function load() {
	try {
		lockdown.value = await fetchLockdown()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the lockdown history', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The lockdown history could not be loaded. Please reload the page.'))
	}
}

onMounted(load)
// A lockdown started or ended in the status banner shows up here at once.
watch(() => state.status?.extensions.lockdown, load)

/**
 * @param entry - A lockdown
 */
function ended(entry: LockdownEntry): string {
	if (entry.endedAt === null) {
		return t(APP_ID, 'Running')
	}
	if (entry.endedBy === 'automatic') {
		return t(APP_ID, 'Ended as planned after {duration}', { duration: formatDuration(Math.max(60, Math.round((entry.endedAt - entry.startedAt) / 60) * 60)) })
	}
	return t(APP_ID, 'Ended early by {actor}', { actor: actorLabel(entry.endedBy ?? '') }, undefined, opts)
}
</script>

<template>
	<SectionCard id="lockdown" :heading="t(APP_ID, 'Lockdown')" :icon="mdiLockAlertOutline">
		<template #description>
			{{ t(APP_ID, 'Start a lockdown from the status banner at the top when your server is under attack. Here you find the earlier lockdowns and what a lockdown does by default.') }}
		</template>

		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<SkeletonBlock v-else-if="lockdown === null" height="120px" />
		<NcEmptyContent
			v-else-if="lockdown.history.length === 0"
			:name="t(APP_ID, 'No lockdown so far')"
			:description="t(APP_ID, 'Let us hope it stays that way. Every lockdown will be listed here.')">
			<template #icon>
				<NcIconSvgWrapper :path="mdiLockAlertOutline" />
			</template>
		</NcEmptyContent>
		<ul v-else :class="$style.history" data-test="lockdown-history">
			<li v-for="entry in lockdown.history" :key="entry.id" :class="$style.entry">
				<span :class="[$style.entry__dot, { [$style.entry__dot_running]: entry.endedAt === null }]" aria-hidden="true" />
				<div :class="$style.entry__text">
					<span :class="$style.entry__title">
						<NcDateTime :timestamp="entry.startedAt * 1000" :relativeTime="false" />
						· {{ t(APP_ID, 'started by {actor}', { actor: actorLabel(entry.startedBy) }, undefined, opts) }}
					</span>
					<span v-if="entry.reason" :class="$style.entry__reason">“{{ entry.reason }}”</span>
					<span :class="$style.entry__meta">{{ ended(entry) }}</span>
				</div>
			</li>
		</ul>

		<SettingsGroup :settings="settings" />
	</SectionCard>
</template>

<style module>
.history {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	list-style: none;
}

.entry {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 2);
	border-bottom: 1px solid var(--color-border);
}

.entry:last-child {
	border-bottom: none;
}

.entry__dot {
	flex: 0 0 auto;
	width: 10px;
	height: 10px;
	margin-top: 7px;
	border-radius: 50%;
	background-color: var(--color-text-maxcontrast);
}

.entry__dot_running {
	background-color: var(--color-error);
}

.entry__text {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 0.5);
	min-width: 0;
}

.entry__title {
	font-weight: 600;
}

.entry__reason {
	overflow-wrap: anywhere;
}

.entry__meta {
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}
</style>
