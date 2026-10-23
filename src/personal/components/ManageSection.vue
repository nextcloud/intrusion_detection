<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { computed, reactive, ref, watchEffect } from 'vue'
import ShowMore from '../../components/common/ShowMore.vue'
import KnownDevices from './KnownDevices.vue'
import LogOutElsewhere from './LogOutElsewhere.vue'
import TrustedNetworks from './TrustedNetworks.vue'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'
import { personal } from '../store.ts'

/** Collapsed until the user opens it; its lists load then */
const open = ref(false)
const summary = computed(() => personal.manage)
/** A part, once offered, stays while the page is open, so that emptying it does not pull the section away */
const parts = reactive({ devices: false, networks: false, otherBrowsers: false })
watchEffect(() => {
	parts.devices ||= summary.value.devices > 0
	parts.networks ||= summary.value.networks > 0
	parts.otherBrowsers ||= summary.value.otherBrowsers > 0
})
const shown = computed(() => parts.devices || parts.networks || parts.otherBrowsers)

const note = computed(() => [
	summary.value.devices > 0 ? n(APP_ID, '%n remembered device', '%n remembered devices', summary.value.devices) : null,
	summary.value.networks > 0 ? n(APP_ID, '%n trusted network', '%n trusted networks', summary.value.networks) : null,
	summary.value.otherBrowsers > 0 ? n(APP_ID, '%n other browser', '%n other browsers', summary.value.otherBrowsers) : null,
].filter((part) => part !== null).join(' · '))
</script>

<template>
	<section
		v-if="shown"
		:aria-label="t(APP_ID, 'Manage')"
		data-test="manage">
		<ShowMore v-model:open="open" :label="t(APP_ID, 'Manage')">
			<template #label>
				<span :class="$style.manage__label">{{ t(APP_ID, 'Manage') }}</span>
				<span :class="$style.manage__note">{{ note }}</span>
			</template>
			<div :class="$style.manage__parts">
				<KnownDevices v-if="parts.devices" />
				<TrustedNetworks v-if="parts.networks" />
				<LogOutElsewhere v-if="parts.otherBrowsers" />
			</div>
		</ShowMore>
	</section>
</template>

<style module>
.manage__label,
.manage__note {
	display: block;
}

.manage__label {
	padding-block-start: var(--ids-space-1);
}

.manage__note {
	composes: muted from '../../styles/shared.module.css';
	padding-block-end: var(--ids-space-1);
	font-weight: normal;
}

.manage__parts {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-6);
	padding-block-start: var(--ids-space-2);
}
</style>
