<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { CheckRef } from '../../types.ts'

import { mdiArrowRight } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import StateBadge from './StateBadge.vue'
import { APP_ID } from '../../utils/format.ts'

const props = defineProps<{
	check: CheckRef
}>()

const state = computed(() => {
	const { effective, configured, reason } = props.check.mode
	// Learning mode is shown once in the status strip; here the check keeps its own mode.
	if (effective === 'protect' || (reason === 'learning' && configured === 'protect')) {
		return { type: 'success' as const, text: t(APP_ID, 'Protect') }
	}
	if (effective === 'observe') {
		return { type: 'info' as const, text: t(APP_ID, 'Observe') }
	}
	return { type: 'warning' as const, text: t(APP_ID, 'Off') }
})
</script>

<template>
	<a :class="$style.note" :href="`#checks/${check.id}`">
		<span :class="$style.note__name">{{ check.name }}</span>
		<StateBadge :type="state.type">
			<span class="hidden-visually">{{ t(APP_ID, 'Mode:') }}</span>
			{{ state.text }}
		</StateBadge>
		<NcIconSvgWrapper
			inline
			:class="$style.note__arrow"
			:path="mdiArrowRight"
			:size="18"
			:name="t(APP_ID, 'Open the check')" />
	</a>
</template>

<style module>
.note {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-2);
	min-height: 34px;
	padding-block: var(--ids-space-1);
	padding-inline: var(--ids-space-3) var(--ids-space-2);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
	color: var(--color-main-text);
	font-weight: 600;
	text-decoration: none;
}

.note:hover,
.note:focus-visible {
	background-color: var(--color-background-hover);
}

.note:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: 2px;
}

.note__arrow {
	color: var(--color-text-maxcontrast);
}

[dir='rtl'] .note__arrow {
	transform: scaleX(-1);
}
</style>
