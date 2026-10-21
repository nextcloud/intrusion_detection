<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'

defineProps<{
	icon: string
	text: string
}>()
</script>

<template>
	<p :class="$style.empty" data-test="empty">
		<span :class="$style.empty__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="icon" :size="20" />
		</span>
		<span>{{ text }}</span>
	</p>
</template>

<style module>
.empty {
	display: flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.empty__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-main-background);
	color: var(--color-success-text);
}
</style>
