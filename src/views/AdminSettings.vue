<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiBookOpenVariant } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AdminTabs from '../components/AdminTabs.vue'
import StatusBanner from '../components/StatusBanner.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { visibleTabs } from '../extensions.ts'
import { openDetectionId, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const tabs = computed(() => visibleTabs())
const activeTab = ref('overview')
const currentTab = computed(() => tabs.value.find((tab) => tab.id === activeTab.value) ?? tabs.value[0])
const openCheckId = ref<string | null>(null)
const { message } = useAnnouncer()

const counts = computed(() => ({ blocks: state.status?.activeBans ?? 0 }))

/**
 * Switch tabs from inside a tab, e.g. "Show recent detections" on a check card.
 *
 * @param tab - The tab id
 */
function showTab(tab: string) {
	activeTab.value = tab
	document.getElementById('ids-tabs')?.scrollIntoView({ block: 'start', behavior: 'smooth' })
}
provide('ids-show-tab', showTab)
provide('ids-open-check', openCheckId)

/**
 * Deep links: #checks, #checks/credential_stuffing, #detection-42, …
 */
function readHash() {
	const hash = decodeURIComponent(window.location.hash.slice(1))
	const detection = hash.match(/^detection-(\d+)$/)
	if (detection) {
		openDetectionId.value = Number(detection[1])
		activeTab.value = 'overview'
		return
	}
	const [tab, item] = hash.split('/')
	if (tab && tabs.value.some((t) => t.id === tab)) {
		activeTab.value = tab
		openCheckId.value = tab === 'checks' && item ? item : null
	}
}

watch(activeTab, (tab) => {
	const hash = '#' + tab
	if (window.location.hash !== hash && !window.location.hash.startsWith(hash + '/')) {
		window.history.replaceState(null, '', hash)
	}
})

onMounted(() => {
	readHash()
	window.addEventListener('hashchange', readHash)
})
onBeforeUnmount(() => window.removeEventListener('hashchange', readHash))
</script>

<template>
	<div :class="$style.page">
		<header :class="$style.page__header">
			<div :class="$style.page__heading">
				<h2 :class="$style.page__title">
					{{ t(APP_ID, 'Intrusion detection') }}
				</h2>
				<p :class="$style.page__description">
					{{ t(APP_ID, 'Recognises attacks on logins, shares and accounts, and answers them with graduated responses. Every decision is explained here, in plain words.') }}
				</p>
			</div>
			<NcButton
				v-if="state.docUrl"
				variant="tertiary"
				:href="state.docUrl"
				target="_blank"
				rel="noreferrer noopener">
				<template #icon>
					<NcIconSvgWrapper :path="mdiBookOpenVariant" />
				</template>
				{{ t(APP_ID, 'Documentation') }}
			</NcButton>
		</header>

		<StatusBanner v-if="state.status" :status="state.status" />
		<NcNoteCard v-else type="error" :text="t(APP_ID, 'The status could not be loaded. Please reload the page.')" />

		<div id="ids-tabs" :class="$style.page__tabs">
			<AdminTabs v-model="activeTab" :tabs="tabs" :counts="counts" />
			<div
				v-if="currentTab"
				:id="`ids-panel-${currentTab.id}`"
				role="tabpanel"
				:aria-labelledby="`ids-tab-${currentTab.id}`">
				<KeepAlive>
					<component :is="currentTab.component" :key="currentTab.id" />
				</KeepAlive>
			</div>
		</div>

		<div class="hidden-visually" aria-live="polite" aria-atomic="true">
			{{ message }}
		</div>
	</div>
</template>

<style module>
.page {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 6);
	width: min(1200px, 100% - var(--default-grid-baseline) * 14);
	margin: calc(var(--default-grid-baseline) * 7);
	padding-bottom: calc(var(--default-grid-baseline) * 10);
}

.page__header {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
}

.page__heading {
	flex: 1 1 400px;
}

.page__title {
	margin: 0;
	font-size: 1.6em;
	font-weight: 700;
}

.page__description {
	margin-block: calc(var(--default-grid-baseline) * 2) 0;
	max-width: 75ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.page__tabs {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	scroll-margin-top: calc(var(--default-grid-baseline) * 4);
}

@media (max-width: 600px) {
	.page {
		width: calc(100% - var(--default-grid-baseline) * 8);
		margin: calc(var(--default-grid-baseline) * 4);
	}
}
</style>
