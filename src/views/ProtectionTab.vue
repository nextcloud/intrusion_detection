<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ref } from 'vue'

import { mdiShieldOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, inject, nextTick, onActivated, ref, watch } from 'vue'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import CheckRow from '../components/checks/CheckRow.vue'
import ProtectionLevelPicker from '../components/checks/ProtectionLevelPicker.vue'
import { refreshProtectionLevel, state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'
import { protectionGroups } from '../utils/protection.ts'

const openCheckId = inject<Ref<string | null>>('ids-open-check', ref(null))

const groups = computed(() => protectionGroups(state.checks))

// A block duration changed on another tab can make the level "custom".
onActivated(refreshProtectionLevel)

watch(openCheckId, async (checkId) => {
	if (checkId) {
		await nextTick()
		document.getElementById(`check-${checkId}`)?.scrollIntoView({ block: 'start', behavior: 'smooth' })
	}
}, { immediate: true })
</script>

<template>
	<div :class="$style.protection">
		<div :class="$style.card">
			<ProtectionLevelPicker />
		</div>

		<NcEmptyContent
			v-if="groups.length === 0"
			:name="t(APP_ID, 'No checks are installed yet')"
			:description="t(APP_ID, 'Blocks you add by hand on the Blocks tab still apply.')">
			<template #icon>
				<NcIconSvgWrapper :path="mdiShieldOutline" />
			</template>
		</NcEmptyContent>

		<section
			v-for="group in groups"
			:key="group.id"
			:class="$style.card"
			:aria-labelledby="`ids-group-${group.id}`"
			data-test="protection-group">
			<h3 :id="`ids-group-${group.id}`" :class="$style.group__heading">
				{{ group.name }}
			</h3>
			<ul :class="$style.group__list">
				<CheckRow
					v-for="check in group.checks"
					:key="check.id"
					:check="check"
					:open="openCheckId === check.id" />
			</ul>
		</section>
	</div>
</template>

<style module>
.protection {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.card {
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.group__heading {
	margin: 0 0 calc(var(--default-grid-baseline) * 1);
	font-size: 1.15em;
	font-weight: 700;
}

.group__list {
	margin: 0;
	padding: 0;
	list-style: none;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	}
}
</style>
