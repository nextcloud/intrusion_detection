<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Status } from '../types.ts'

import { mdiAlertOutline } from '@mdi/js'
import { getCanonicalLocale, n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID } from '../utils/format.ts'
import { statusIcon } from '../utils/status.ts'

const props = defineProps<{
	status: Status
	/** Logins that wait for this administrator's approval */
	waiting?: number
}>()

const emit = defineEmits<{
	/** The admin wants to see what needs attention */
	attention: []
}>()

const sentence = computed(() => {
	switch (props.status.state) {
		case 'learning': {
			const until = new Date(props.status.learning.until * 1000).toLocaleDateString(getCanonicalLocale(), { weekday: 'long', day: 'numeric', month: 'long' })
			return t(APP_ID, 'Learning until {date}: checks only record what they would do.', { date: until })
		}
		case 'off':
			return t(APP_ID, 'Off: nothing is checked and nobody is blocked.')
		default:
			return t(APP_ID, 'Protecting this server.')
	}
})

const attention = computed(() => props.status.problems.filter((problem) => problem.level !== 'info').length + (props.waiting ?? 0))
</script>

<template>
	<div
		:class="[$style.strip, $style[`strip_${status.state}`]]"
		role="status"
		data-test="status-strip">
		<span :class="$style.strip__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="statusIcon(status.state)" :size="18" />
		</span>
		<span :class="$style.strip__sentence">{{ sentence }}</span>
		<button
			v-if="attention > 0"
			type="button"
			:class="$style.strip__link"
			@click="emit('attention')">
			<NcIconSvgWrapper inline :path="mdiAlertOutline" :size="18" />
			{{ n(APP_ID, '%n thing needs attention', '%n things need attention', attention) }}
		</button>
	</div>
</template>

<style module>
.strip {
	--state-color: var(--color-success);
	--state-text: var(--color-success-text);
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-1) var(--ids-space-2);
}

.strip_learning {
	--state-color: var(--color-info);
	--state-text: var(--color-info-text);
}

.strip_off {
	--state-color: var(--color-warning);
	--state-text: var(--color-warning-text);
}

.strip__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 28px;
	height: 28px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--state-color) 18%, var(--color-main-background));
	color: var(--state-text);
}

.strip__sentence {
	flex: 1 1 12em;
	min-width: 0;
	font-weight: 600;
}

.strip button.strip__link {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	min-height: calc(var(--default-clickable-area) - var(--ids-space-2));
	margin: 0;
	padding-inline: var(--ids-space-2);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-warning-text);
	font-weight: 600;
	cursor: pointer;
}

.strip button.strip__link:hover {
	background-color: var(--color-background-hover);
}

.strip button.strip__link:focus-visible {
	outline: var(--ids-focus-ring);
	outline-offset: 2px;
}
</style>
