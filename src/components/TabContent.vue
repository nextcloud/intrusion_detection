<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { TabDefinition } from '../extensions.ts'

import { computed } from 'vue'
import { sectionsOf } from '../extensions.ts'
import { advanced } from '../store.ts'

const props = defineProps<{
	tab: TabDefinition
}>()

const sections = computed(() => sectionsOf(props.tab.id, advanced.value))
</script>

<template>
	<component :is="tab.component" v-if="tab.component && sections.length === 0" />
	<div v-else :class="$style.content">
		<component :is="tab.component" v-if="tab.component" />
		<component :is="section.component" v-for="section in sections" :key="section.id" />
	</div>
</template>

<style module>
.content {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}
</style>
