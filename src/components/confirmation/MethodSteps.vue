<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationMethod, ConfirmationMethodId } from '../../types.ts'

import { mdiAccountCheckOutline, mdiAlertOutline, mdiCheckCircleOutline, mdiCloseCircleOutline, mdiEmailOutline, mdiLaptop, mdiTwoFactorAuthentication } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import StateBadge from '../common/StateBadge.vue'
import { APP_ID } from '../../utils/format.ts'

defineProps<{
	/** In the order they are tried */
	methods: ConfirmationMethod[]
}>()

const icons: Record<ConfirmationMethodId, string> = {
	second_factor: mdiTwoFactorAuthentication,
	known_device: mdiLaptop,
	email_code: mdiEmailOutline,
	admin_approval: mdiAccountCheckOutline,
}

const badges = {
	on: { type: 'success', icon: mdiCheckCircleOutline, text: () => t(APP_ID, 'On') },
	off: { type: 'neutral', icon: mdiCloseCircleOutline, text: () => t(APP_ID, 'Off') },
	unavailable: { type: 'warning', icon: mdiAlertOutline, text: () => t(APP_ID, 'Not available') },
} as const
</script>

<template>
	<ol :class="$style.steps" data-test="methods">
		<li
			v-for="(method, index) in methods"
			:key="method.id"
			:class="[$style.step, { [$style.step_inactive]: method.state !== 'on' }]"
			:data-method="method.id">
			<div :class="$style.step__head">
				<span :class="$style.step__icon" aria-hidden="true">
					<NcIconSvgWrapper :path="icons[method.id]" :size="22" />
					<span :class="$style.step__number">{{ index + 1 }}</span>
				</span>
				<StateBadge :type="badges[method.state].type" :icon="badges[method.state].icon">
					{{ badges[method.state].text() }}
				</StateBadge>
			</div>
			<h4 :class="$style.step__name">
				{{ method.name }}
			</h4>
			<p :class="$style.step__text">
				{{ method.description }}
			</p>
			<p v-if="method.note" :class="$style.step__note">
				{{ method.note }}
			</p>
		</li>
	</ol>
</template>

<style module>
.steps {
	composes: plainList from '../../styles/shared.module.css';
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr));
	gap: var(--ids-space-3);
	counter-reset: none;
}

.step {
	position: relative;
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding: var(--ids-space-4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.step_inactive {
	background-color: var(--color-background-hover);
}

.step__head {
	display: flex;
	align-items: center;
	justify-content: space-between;
	gap: var(--ids-space-2);
}

.step__icon {
	position: relative;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	width: 40px;
	height: 40px;
	border-radius: 50%;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.step_inactive .step__icon {
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.step__number {
	position: absolute;
	inset-block-start: -4px;
	inset-inline-end: -6px;
	display: inline-flex;
	align-items: center;
	justify-content: center;
	min-width: 20px;
	height: 20px;
	border: 2px solid var(--color-main-background);
	border-radius: 10px;
	background-color: var(--color-primary-element);
	color: var(--color-primary-element-text);
	font-size: 0.75em;
	font-weight: 700;
}

.step_inactive .step__number {
	background-color: var(--color-text-maxcontrast);
	color: var(--color-main-background);
}

.step__name {
	margin: 0;
	font-size: 1em;
	font-weight: 700;
}

.step__text,
.step__note {
	margin: 0;
	line-height: 1.5;
}

.step__text {
	composes: muted from '../../styles/shared.module.css';
}

.step__note {
	padding-inline-start: var(--ids-space-2);
	border-inline-start: 3px solid var(--color-warning);
	font-size: 0.9em;
}
</style>
