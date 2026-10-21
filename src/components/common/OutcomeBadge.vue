<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DetectionOutcome } from '../../types.ts'

import { computed } from 'vue'
import { outcomeLabel } from '../../utils/format.ts'

/** What Nextcloud did about a detection, in one word */
const props = defineProps<{
	outcome: DetectionOutcome
}>()

const label = computed(() => outcomeLabel(props.outcome))
</script>

<template>
	<span :class="[$style.badge, $style[`badge_${outcome}`]]" data-test="outcome">{{ label }}</span>
</template>

<style module>
.badge {
	display: inline-block;
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border: 1px solid transparent;
	border-radius: var(--border-radius-element);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 22px;
	white-space: nowrap;
}

.badge_acted {
	background-color: var(--color-primary-element);
	color: var(--color-primary-element-text);
}

.badge_notified {
	border-color: var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.badge_recorded {
	border-color: var(--color-border-dark, var(--color-border));
	background-color: var(--color-background-hover);
	color: var(--color-main-text);
}

.badge_observed {
	border-style: dashed;
	border-color: var(--color-primary-element);
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}
</style>
