<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'

withDefaults(defineProps<{
	type?: 'neutral' | 'active' | 'info' | 'success' | 'warning' | 'error'
	/** An icon, so that colour is never the only signal */
	icon?: string
}>(), {
	type: 'neutral',
	icon: undefined,
})
</script>

<template>
	<span :class="[$style.badge, $style[`badge_${type}`]]">
		<NcIconSvgWrapper
			v-if="icon"
			inline
			:path="icon"
			:size="16" />
		<slot />
	</span>
</template>

<style module>
.badge {
	--badge-color: var(--color-text-maxcontrast);
	--badge-background: var(--color-background-dark);
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	padding-block: var(--ids-space-half);
	padding-inline: var(--ids-space-2-5);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--badge-background);
	color: var(--badge-color);
	font-size: 0.85em;
	line-height: 1.5;
	white-space: nowrap;
}

.badge > :first-child:not(:only-child) {
	margin-inline-start: calc(var(--default-grid-baseline) * -1);
}

.badge_active {
	--badge-color: var(--color-primary-element-light-text);
	--badge-background: var(--color-primary-element-light);
	font-weight: 600;
}

.badge_info {
	--badge-color: var(--color-info-text);
	--badge-background: color-mix(in srgb, var(--color-info) 14%, var(--color-main-background));
}

.badge_success {
	--badge-color: var(--color-success-text);
	--badge-background: color-mix(in srgb, var(--color-success) 14%, var(--color-main-background));
	font-weight: 600;
}

.badge_warning {
	--badge-color: var(--color-warning-text);
	--badge-background: color-mix(in srgb, var(--color-warning) 16%, var(--color-main-background));
	font-weight: 600;
}

.badge_error {
	--badge-color: var(--color-error-text);
	--badge-background: color-mix(in srgb, var(--color-error) 14%, var(--color-main-background));
	font-weight: 600;
}
</style>
