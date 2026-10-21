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
	--pill-background: var(--color-background-dark);
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1.5);
	padding-block: calc(var(--default-grid-baseline) / 2);
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-pill, 100px);
	background-color: var(--pill-background);
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
	--pill-background: color-mix(in srgb, var(--color-info) 14%, var(--color-main-background));
}

.pill_high {
	--pill-color: var(--color-warning-text);
	--pill-background: color-mix(in srgb, var(--color-warning) 16%, var(--color-main-background));
}

.pill_critical {
	--pill-color: var(--color-error-text);
	--pill-background: color-mix(in srgb, var(--color-error) 14%, var(--color-main-background));
}
</style>
