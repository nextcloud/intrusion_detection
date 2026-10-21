<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Blocklist, Blocklists } from '../../types.ts'

import { mdiCloudOutline, mdiPlaylistRemove, mdiPlus, mdiShieldAlertOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onActivated, onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import CheckStateNote from '../common/CheckStateNote.vue'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import AddBlocklistDialog from './AddBlocklistDialog.vue'
import BlocklistRow from './BlocklistRow.vue'
import { errorMessage, fetchBlocklists } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const data = ref<Blocklists | null>(null)
const loadError = ref<string | null>(null)
const adding = ref(false)

const denyLists = computed(() => data.value?.lists.filter((l) => l.purpose === 'deny') ?? [])
const attributeLists = computed(() => data.value?.lists.filter((l) => l.purpose !== 'deny') ?? [])
const checkRuns = computed(() => data.value?.check.mode.effective !== 'off')
const enabledDeny = computed(() => denyLists.value.some((l) => l.enabled))
const downloadSettings = computed(() => state.settings.filter((s) => s.group === 'blocklists'))

/**
 * Load the lists.
 */
async function load() {
	try {
		data.value = await fetchBlocklists()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the blocklists', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The lists could not be loaded. Please reload the page.'))
	}
}

onMounted(load)
onActivated(load)

/**
 * @param list - The list as the server returned it
 */
function replace(list: Blocklist) {
	if (data.value === null) {
		return
	}
	const index = data.value.lists.findIndex((l) => l.id === list.id)
	if (index === -1) {
		data.value.lists.push(list)
	} else {
		data.value.lists.splice(index, 1, list)
	}
}

/**
 * @param id - The removed list
 */
function removed(id: string) {
	if (data.value !== null) {
		data.value.lists = data.value.lists.filter((l) => l.id !== id)
	}
}
</script>

<template>
	<SectionCard :heading="t(APP_ID, 'Blocklists and network lists')" :icon="mdiPlaylistRemove">
		<template #description>
			{{ t(APP_ID, 'Lists that others publish: addresses known for attacks, and the networks of hosting providers and Tor. Nextcloud downloads the lists you switch on and checks addresses against its own copy, so nothing about your users is sent anywhere.') }}
		</template>
		<template #actions>
			<NcButton variant="secondary" :disabled="data === null || data.lists.length >= data.maxLists" @click="adding = true">
				<template #icon>
					<NcIconSvgWrapper :path="mdiPlus" />
				</template>
				{{ t(APP_ID, 'Add a list') }}
			</NcButton>
		</template>

		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 3" :key="i" height="72px" />
		</div>

		<template v-else>
			<section :class="$style.group" aria-labelledby="ids-deny-lists">
				<div :class="$style.group__head">
					<div>
						<h4 id="ids-deny-lists" :class="$style.group__heading">
							<NcIconSvgWrapper inline :path="mdiShieldAlertOutline" :size="20" />
							{{ t(APP_ID, 'Blocklists') }}
						</h4>
						<p :class="$style.group__text">
							{{ t(APP_ID, 'Addresses known for attacks. In Observe mode a list only counts matching addresses; in Protect mode they get an error page with a reference. Blocklists only work while their check is on:') }}
						</p>
					</div>
					<CheckStateNote :check="data.check" />
				</div>
				<NcNoteCard v-if="enabledDeny && !checkRuns" type="warning">
					{{ t(APP_ID, 'The check "{check}" is off, so the blocklists you switched on are not downloaded and do nothing. Open the check and set it to Observe or Protect.', { check: data.check.name }) }}
				</NcNoteCard>
				<NcNoteCard v-else-if="enabledDeny && !data.countsMatches" type="info">
					{{ t(APP_ID, 'Matches are counted only with a memory cache, so no counts are shown here.') }}
				</NcNoteCard>
				<ul :class="$style.group__list">
					<BlocklistRow
						v-for="list in denyLists"
						:key="list.id"
						:list="list"
						:days="data.matchDays"
						:countsMatches="data.countsMatches"
						:minInterval="data.minInterval"
						:maxInterval="data.maxInterval"
						@updated="replace"
						@removed="removed" />
				</ul>
			</section>

			<section :class="$style.group" aria-labelledby="ids-attribute-lists">
				<div>
					<h4 id="ids-attribute-lists" :class="$style.group__heading">
						<NcIconSvgWrapper inline :path="mdiCloudOutline" :size="20" />
						{{ t(APP_ID, 'Network lists') }}
					</h4>
					<p :class="$style.group__text">
						{{ t(APP_ID, 'These lists never block anyone. They mark addresses that belong to a cloud or hosting provider or to the Tor network. A check that asks for extra confirmation when someone logs in from such a network will use them; it is not installed yet, so switching a list on now only prepares it.') }}
					</p>
				</div>
				<ul :class="$style.group__list">
					<BlocklistRow
						v-for="list in attributeLists"
						:key="list.id"
						:list="list"
						:days="data.matchDays"
						:countsMatches="data.countsMatches"
						:minInterval="data.minInterval"
						:maxInterval="data.maxInterval"
						@updated="replace"
						@removed="removed" />
				</ul>
			</section>

			<section v-if="downloadSettings.length > 0" :class="$style.group" aria-labelledby="ids-list-downloads">
				<h4 id="ids-list-downloads" :class="$style.group__heading">
					{{ t(APP_ID, 'Downloads') }}
				</h4>
				<SettingsGroup :settings="downloadSettings" />
			</section>
		</template>

		<AddBlocklistDialog
			v-model:open="adding"
			:existing="data?.lists.map((l) => l.id) ?? []"
			:formats="data?.formats ?? ['cidr']"
			@added="replace" />
	</SectionCard>
</template>

<style module>
.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
}

.group {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.group__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-end;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.group__head > :first-child {
	flex: 1 1 400px;
}

.group__heading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.group__text {
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	max-width: 80ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.group__list {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 460px), 1fr));
	gap: calc(var(--default-grid-baseline) * 3);
	align-items: start;
	margin: 0;
	padding: 0;
	list-style: none;
}
</style>
