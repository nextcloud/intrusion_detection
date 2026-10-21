<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Blocklist, Blocklists } from '../../types.ts'

import { mdiCloudOutline, mdiPlaylistRemove, mdiPlus, mdiShieldAlertOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
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
import { advanced, state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

const data = ref<Blocklists | null>(null)
const loadError = ref<string | null>(null)
const adding = ref(false)

/** Your own lists are managed with the advanced options only */
const shown = computed(() => data.value?.lists.filter((l) => l.builtin || advanced.value) ?? [])
const denyLists = computed(() => shown.value.filter((l) => l.purpose === 'deny'))
const attributeLists = computed(() => shown.value.filter((l) => l.purpose !== 'deny'))
const checkRuns = computed(() => data.value?.check.mode.effective !== 'off')
const enabledDeny = computed(() => denyLists.value.some((l) => l.enabled))
const enabledAttribute = computed(() => attributeLists.value.some((l) => l.enabled))
const networkCheckRuns = computed(() => data.value?.networkCheck.mode.effective !== 'off')
const riskEnabled = computed(() => state.settings.find((s) => s.name === 'risk_enabled')?.value !== false)
const customCount = computed(() => data.value?.lists.filter((l) => !l.builtin).length ?? 0)
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
			{{ t(APP_ID, 'Lists that others publish. Nextcloud downloads the ones you switch on and checks against its own copy, so nothing about your users is sent anywhere.') }}
		</template>
		<template v-if="advanced" #actions>
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
							{{ t(APP_ID, 'Addresses known for attacks. Observe only counts them; Protect shows them an error page with a reference.') }}
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
				<div :class="$style.group__head">
					<div>
						<h4 id="ids-attribute-lists" :class="$style.group__heading">
							<NcIconSvgWrapper inline :path="mdiCloudOutline" :size="20" />
							{{ t(APP_ID, 'Network lists') }}
						</h4>
						<p :class="$style.group__text">
							{{ t(APP_ID, 'These never block anyone. A password login from a hosting provider or the Tor network needs extra confirmation.') }}
						</p>
					</div>
					<CheckStateNote :check="data.networkCheck" />
				</div>
				<NcNoteCard v-if="enabledAttribute && !networkCheckRuns && !riskEnabled" type="warning">
					{{ t(APP_ID, 'The check "{check}" is off and the risk score is off, so the network lists you switched on are not used. Open the check and set it to Observe or Protect.', { check: data.networkCheck.name }) }}
				</NcNoteCard>
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

			<p v-if="!advanced && customCount > 0" :class="$style.group__text" data-test="custom-lists-hint">
				{{ n(APP_ID, 'You added %n list of your own. Show the advanced options to manage it.', 'You added %n lists of your own. Show the advanced options to manage them.', customCount) }}
			</p>

			<section v-if="advanced && downloadSettings.length > 0" :class="$style.group" aria-labelledby="ids-list-downloads">
				<h4 id="ids-list-downloads" :class="$style.group__heading">
					{{ t(APP_ID, 'Downloads') }}
				</h4>
				<SettingsGroup :settings="downloadSettings" />
			</section>
		</template>

		<AddBlocklistDialog
			v-if="advanced"
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
