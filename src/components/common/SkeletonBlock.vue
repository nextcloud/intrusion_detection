<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
withDefaults(defineProps<{
	height?: string
	width?: string
}>(), {
	height: '1em',
	width: '100%',
})
</script>

<template>
	<span :class="$style.skeleton" :style="{ height, width }" aria-hidden="true" />
</template>

<style module>
.skeleton {
	display: block;
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-dark);
	animation: skeleton-pulse 1.4s ease-in-out infinite;
}

@keyframes skeleton-pulse {
	0%, 100% {
		opacity: 1;
	}

	50% {
		opacity: 0.45;
	}
}

@media (prefers-reduced-motion: reduce) {
	.skeleton {
		animation: none;
	}
}
</style>
