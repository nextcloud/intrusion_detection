<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Status } from '../types.ts'

import { mdiAlertOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { APP_ID, formatNumber } from '../utils/format.ts'
import { statusIcon, statusTitle } from '../utils/status.ts'

const props = defineProps<{
	status: Status
}>()

const emit = defineEmits<{
	/** The admin wants the full status on the Overview tab */
	overview: []
}>()

const summary = computed(() => {
	const last = props.status.last24h
	return t(APP_ID, '{detections} and {blocks} in the last 24 hours', {
		detections: n(APP_ID, '{count} detection', '{count} detections', last.detections, { count: formatNumber(last.detections) }),
		blocks: n(APP_ID, '{count} active block', '{count} active blocks', props.status.activeBans, { count: formatNumber(props.status.activeBans) }),
	})
})

const attention = computed(() => props.status.problems.filter((problem) => problem.level !== 'info').length)
</script>

<template>
	<section
		:class="[$style.strip, $style[`strip_${status.state}`]]"
		:aria-label="t(APP_ID, 'Status')"
		data-test="status-strip">
		<span :class="$style.strip__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="statusIcon(status.state)" :size="18" />
		</span>
		<strong :class="$style.strip__title">{{ statusTitle(status) }}</strong>
		<span :class="$style.strip__summary">{{ summary }}</span>
		<button
			type="button"
			:class="[$style.strip__link, { [$style.strip__link_warning]: attention > 0 }]"
			@click="emit('overview')">
			<NcIconSvgWrapper
				v-if="attention > 0"
				inline
				:path="mdiAlertOutline"
				:size="18" />
			{{ attention > 0
				? n(APP_ID, '%n thing to look at', '%n things to look at', attention)
				: t(APP_ID, 'Overview') }}
		</button>
	</section>
</template>

<style module>
.strip {
	--state-color: var(--color-success);
	--state-text: var(--color-success-text);
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 3);
	padding-block: calc(var(--default-grid-baseline) * 1.5);
	padding-inline: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 1.5);
	border: 1px solid color-mix(in srgb, var(--state-color) 30%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--state-color) 10%, var(--color-main-background));
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
	width: 30px;
	height: 30px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--state-color) 20%, var(--color-main-background));
	color: var(--state-text);
}

.strip__title {
	color: var(--state-text);
}

.strip__summary {
	flex: 1 1 auto;
	min-width: 0;
	color: var(--color-text-maxcontrast);
}

.strip button.strip__link {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	min-height: calc(var(--default-clickable-area) - var(--default-grid-baseline) * 2);
	margin: 0;
	padding-inline: calc(var(--default-grid-baseline) * 3);
	border: none;
	border-radius: var(--border-radius-element);
	background: transparent;
	color: var(--color-main-text);
	font-weight: 600;
	cursor: pointer;
}

.strip button.strip__link:hover {
	background-color: color-mix(in srgb, var(--state-color) 16%, var(--color-main-background));
}

.strip button.strip__link:focus-visible {
	outline: 2px solid var(--color-main-text);
	outline-offset: 2px;
}

.strip button.strip__link_warning {
	color: var(--color-warning-text);
}

@media (max-width: 600px) {
	.strip__summary {
		display: none;
	}

	.strip button.strip__link {
		margin-inline-start: auto;
	}
}
</style>
