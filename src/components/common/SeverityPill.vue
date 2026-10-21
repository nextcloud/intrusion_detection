<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Severity } from '../../types.ts'

import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	severity: Severity
}>()

const label = computed(() => ({
	low: t(APP_ID, 'Low'),
	medium: t(APP_ID, 'Medium'),
	high: t(APP_ID, 'High'),
	critical: t(APP_ID, 'Critical'),
})[props.severity] ?? props.severity)
</script>

<template>
	<span :class="[$style.pill, $style[`pill_${severity}`]]">
		<span :class="$style.pill__dot" aria-hidden="true" />
		<span class="hidden-visually">{{ t(APP_ID, 'Severity:') }}</span>
		{{ label }}
	</span>
</template>

<style module>
.pill {
	--pill-color: var(--color-text-maxcontrast);
	--pill-tint: var(--color-text-maxcontrast);
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	padding-block: calc(var(--default-grid-baseline) / 2);
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border: 1px solid color-mix(in srgb, var(--pill-tint) 35%, transparent);
	border-radius: var(--border-radius-pill, 100px);
	background-color: color-mix(in srgb, var(--pill-tint) 16%, var(--color-main-background));
	color: var(--pill-color);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 1.4;
	white-space: nowrap;
}

.pill__dot {
	width: 7px;
	height: 7px;
	border-radius: 50%;
	background-color: currentColor;
}

.pill_medium {
	--pill-color: var(--color-info-text);
	--pill-tint: var(--color-info);
}

.pill_high {
	--pill-color: var(--color-warning-text);
	--pill-tint: var(--color-warning);
}

.pill_critical {
	--pill-color: var(--color-error-text);
	--pill-tint: var(--color-error);
}
</style>
