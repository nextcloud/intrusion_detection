<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Ref } from 'vue'

import { mdiShieldOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed, inject, nextTick, ref, watch } from 'vue'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import CheckCard from '../components/checks/CheckCard.vue'
import { state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

const openCheckId = inject<Ref<string | null>>('ids-open-check', ref(null))

const groups = computed(() => state.categories
	.map((category) => ({ ...category, checks: state.checks.filter((check) => check.category === category.id) }))
	.filter((group) => group.checks.length > 0))

watch(openCheckId, async (id) => {
	if (id) {
		await nextTick()
		document.getElementById(`check-${id}`)?.scrollIntoView({ block: 'start', behavior: 'smooth' })
	}
}, { immediate: true })
</script>

<template>
	<div :class="$style.checks">
		<p :class="$style.checks__intro">
			{{ t(APP_ID, 'Each check watches for one kind of attack. Observe records what it finds; Protect also acts, with the responses you choose.') }}
		</p>

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
			:class="$style.group"
			:aria-labelledby="`ids-group-${group.id}`">
			<h3 :id="`ids-group-${group.id}`" :class="$style.group__heading">
				{{ group.name }}
				<span :class="$style.group__count">{{ group.checks.length }}</span>
			</h3>
			<div :class="$style.group__grid">
				<CheckCard
					v-for="check in group.checks"
					:key="check.id"
					:check="check"
					:open="openCheckId === check.id" />
			</div>
		</section>
	</div>
</template>

<style module>
.checks {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 6);
}

.checks__intro {
	margin: 0;
	max-width: 80ch;
	color: var(--color-text-maxcontrast);
	line-height: 1.55;
}

.group {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.group__heading {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.group__count {
	min-width: 22px;
	padding-inline: calc(var(--default-grid-baseline) * 1.5);
	border-radius: 11px;
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
	font-size: 0.75em;
	line-height: 22px;
	text-align: center;
}

.group__grid {
	display: grid;
	grid-template-columns: repeat(auto-fill, minmax(min(100%, 420px), 1fr));
	gap: calc(var(--default-grid-baseline) * 4);
}
</style>
