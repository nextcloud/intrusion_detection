<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Segment } from '../../utils/format.ts'

defineProps<{
	segments: Segment[]
	/** Settings whose value is being edited, highlighted more strongly */
	changed?: string[]
}>()
</script>

<template>
	<span>
		<template v-for="(segment, index) in segments" :key="index">
			<strong
				v-if="segment.name"
				:class="[$style.token, { [$style.token_changed]: changed?.includes(segment.name) }]"
				:data-setting="segment.name">{{ segment.text }}</strong>
			<span v-else v-text="segment.text" />
		</template>
	</span>
</template>

<style module>
.token {
	padding-inline: 3px;
	border-radius: var(--border-radius-small, 4px);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
	font-weight: 600;
	white-space: nowrap;
	transition: background-color 150ms ease, box-shadow 150ms ease;
}

.token_changed {
	box-shadow: 0 0 0 2px var(--color-primary-element);
}

@media (prefers-reduced-motion: reduce) {
	.token {
		transition: none;
	}
}
</style>
