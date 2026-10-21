<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { mdiBookOpenVariant } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import AdminTabs from '../components/AdminTabs.vue'
import StatusBanner from '../components/StatusBanner.vue'
import StatusStrip from '../components/StatusStrip.vue'
import TabContent from '../components/TabContent.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { visibleTabs } from '../extensions.ts'
import { advanced, openDetectionId, setAdvanced, state } from '../store.ts'
import { resolveLink } from '../utils/deepLinks.ts'
import { APP_ID } from '../utils/format.ts'

const tabs = computed(() => visibleTabs(advanced.value))
const activeTab = ref('overview')
const currentTab = computed(() => tabs.value.find((tab) => tab.id === activeTab.value) ?? tabs.value[0])
const openCheckId = ref<string | null>(null)
const { message } = useAnnouncer()

const counts = computed(() => ({ blocks: state.status?.activeBans ?? 0 }))

/**
 * Scroll to a section of the current tab once it is rendered; tabs load
 * their parts asynchronously, so it is looked for a few times.
 *
 * @param section - The section, element id `ids-section-<section>`
 */
async function scrollToSection(section: string) {
	for (let attempt = 0; attempt < 20; attempt++) {
		await nextTick()
		const element = document.getElementById(`ids-section-${section}`)
		if (element) {
			element.scrollIntoView({ block: 'start', behavior: 'smooth' })
			return
		}
		await new Promise((resolve) => setTimeout(resolve, 100))
	}
}

/**
 * Follow a link of the page, e.g. "#settings/notifications", "#incidents"
 * or a link of a former tab such as "#decoys". A target that is only shown
 * with the advanced options turns them on.
 *
 * @param link - The link, with or without "#"
 * @return whether the page knows the link
 */
function follow(link: string): boolean {
	const target = resolveLink(link)
	if (target === null) {
		return false
	}
	if (target.advanced && !advanced.value) {
		setAdvanced(true)
	}
	activeTab.value = target.tab
	openCheckId.value = target.check
	if (target.detection !== null) {
		openDetectionId.value = target.detection
	}
	if (target.section !== null) {
		scrollToSection(target.section)
	}
	return true
}

/**
 * Switch tabs from inside a tab, e.g. "Show recent detections" on a check
 * card; also takes a section, e.g. "settings/notifications".
 *
 * @param link - The tab id, or a link of the page
 */
function showTab(link: string) {
	if (follow(link) && !link.includes('/')) {
		document.getElementById('ids-tabs')?.scrollIntoView({ block: 'start', behavior: 'smooth' })
	}
}
provide('ids-show-tab', showTab)
provide('ids-open-check', openCheckId)

/**
 * The header's "things need attention": the list on the Overview.
 */
function showAttention() {
	activeTab.value = 'overview'
	scrollToSection('attention')
}

/**
 * Deep links: #protection, #protection/credential_stuffing, #detection-42, …
 */
function readHash() {
	follow(decodeURIComponent(window.location.hash.slice(1)))
}

watch(activeTab, (tab) => {
	const hash = '#' + tab
	if (window.location.hash !== hash && !window.location.hash.startsWith(hash + '/')) {
		window.history.replaceState(null, '', hash)
	}
})

// Hiding the advanced options leaves a tab that is only shown with them.
watch(tabs, (list) => {
	if (!list.some((tab) => tab.id === activeTab.value)) {
		activeTab.value = 'overview'
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
				<StatusStrip v-if="state.status" :status="state.status" @attention="showAttention" />
			</div>
			<div :class="$style.page__actions">
				<NcCheckboxRadioSwitch
					:modelValue="advanced"
					type="switch"
					data-test="advanced-switch"
					@update:modelValue="setAdvanced">
					{{ t(APP_ID, 'Show advanced options') }}
				</NcCheckboxRadioSwitch>
				<NcButton
					v-if="state.docUrl"
					variant="tertiary"
					:href="state.docUrl"
					:aria-label="t(APP_ID, 'Documentation')"
					:title="t(APP_ID, 'Documentation')"
					target="_blank"
					rel="noreferrer noopener">
					<template #icon>
						<NcIconSvgWrapper :path="mdiBookOpenVariant" />
					</template>
				</NcButton>
			</div>
		</header>

		<div id="ids-tabs" :class="$style.page__tabs">
			<AdminTabs v-model="activeTab" :tabs="tabs" :counts="counts" />
			<div
				v-if="currentTab"
				:id="`ids-panel-${currentTab.id}`"
				:class="$style.page__panel"
				role="tabpanel"
				:aria-labelledby="`ids-tab-${currentTab.id}`">
				<NcNoteCard v-if="!state.status" type="error" :text="t(APP_ID, 'The status could not be loaded. Please reload the page.')" />
				<StatusBanner v-else-if="currentTab.id === 'overview'" :status="state.status" />
				<KeepAlive>
					<TabContent :key="currentTab.id" :tab="currentTab" />
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
	display: flex;
	flex: 1 1 400px;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.page__actions {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
}

.page__title {
	margin: 0;
	font-size: 1.6em;
	font-weight: 700;
}

.page__tabs {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	min-width: 0;
	scroll-margin-top: calc(var(--default-grid-baseline) * 4);
}

.page__panel {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
	min-width: 0;
}

@media (max-width: 600px) {
	.page {
		width: calc(100% - var(--default-grid-baseline) * 8);
		margin: calc(var(--default-grid-baseline) * 4);
	}
}
</style>
