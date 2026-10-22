<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import { t } from '@nextcloud/l10n'
import SkeletonBlock from '../../components/common/SkeletonBlock.vue'
import { APP_ID } from '../../utils/format.ts'

withDefaults(defineProps<{
	rows?: number
}>(), {
	rows: 3,
})
</script>

<template>
	<div :class="$style.rows" aria-busy="true" data-test="loading">
		<span class="hidden-visually">{{ t(APP_ID, 'Loading …') }}</span>
		<div v-for="row in rows" :key="row" :class="$style.row">
			<SkeletonBlock width="36px" height="36px" />
			<div :class="$style.row__text">
				<SkeletonBlock width="55%" height="14px" />
				<SkeletonBlock width="80%" height="12px" />
			</div>
		</div>
	</div>
</template>

<style module>
.rows {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
}

.row {
	display: flex;
	align-items: center;
	gap: var(--ids-space-3);
}

.row > :first-child {
	flex: 0 0 auto;
	border-radius: 50%;
}

.row__text {
	display: flex;
	flex: 1 1 auto;
	flex-direction: column;
	gap: var(--ids-space-2);
}
</style>
