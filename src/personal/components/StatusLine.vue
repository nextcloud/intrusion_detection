<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { StatusLevel } from '../types.ts'

import { mdiAccountQuestionOutline, mdiAlertOutline, mdiHistory, mdiInformationOutline, mdiLockReset, mdiShieldAlertOutline, mdiShieldCheckOutline, mdiShieldLockOutline } from '@mdi/js'
import { computed, useId } from 'vue'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import { personal } from '../store.ts'

const id = useId()
const status = computed(() => personal.overview?.status ?? null)

const ICONS: Record<StatusLevel, string> = {
	ok: mdiShieldCheckOutline,
	info: mdiInformationOutline,
	warning: mdiShieldAlertOutline,
}

/** Each detail has its own icon, so colour is never the only signal */
const ITEM_ICONS: Record<string, string> = {
	questions: mdiAccountQuestionOutline,
	password_change: mdiLockReset,
	protected: mdiShieldLockOutline,
	events: mdiHistory,
	failed_logins: mdiAlertOutline,
}
</script>

<template>
	<section
		v-if="status"
		:class="[$style.status, $style[`status_${status.level}`]]"
		:aria-labelledby="id"
		data-test="status">
		<span :class="$style.status__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="ICONS[status.level]" :size="28" />
		</span>
		<div :class="$style.status__text" role="status" aria-live="polite">
			<h3 :id="id" :class="$style.status__headline" data-test="status-headline">
				{{ status.headline }}
			</h3>
			<ul v-if="status.items.length > 0" :class="$style.status__items">
				<li
					v-for="item in status.items"
					:key="item.id"
					:class="$style.status__item"
					:data-test="`status-${item.id}`">
					<NcIconSvgWrapper inline :path="ITEM_ICONS[item.id] ?? mdiInformationOutline" :size="18" />
					<span>{{ item.text }}</span>
				</li>
			</ul>
		</div>
	</section>
</template>

<style module>
.status {
	--status-color: var(--color-success);
	--status-text: var(--color-success-text);
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-4);
	padding: var(--ids-space-5);
	border: 1px solid color-mix(in srgb, var(--status-color) 35%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--status-color) 10%, var(--color-main-background));
}

.status_info {
	--status-color: var(--color-info);
	--status-text: var(--color-info-text);
}

.status_warning {
	--status-color: var(--color-warning);
	--status-text: var(--color-warning-text);
}

.status__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 52px;
	height: 52px;
	border-radius: 50%;
	background-color: color-mix(in srgb, var(--status-color) 22%, var(--color-main-background));
	color: var(--status-text);
}

.status__text {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	min-width: 0;
	padding-block-start: var(--ids-space-1);
}

.status__headline {
	margin: 0;
	font-size: 1.3em;
	font-weight: 600;
	line-height: 1.35;
	overflow-wrap: anywhere;
}

.status__items {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1-5);
	margin: 0;
	padding: 0;
	list-style: none;
}

.status__item {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
	line-height: 1.5;
}

.status__item > :first-child {
	flex: 0 0 auto;
	margin-block-start: 2px;
	color: var(--color-text-maxcontrast);
}

@media (max-width: 480px) {
	.status {
		flex-direction: column;
		gap: var(--ids-space-3);
		padding: var(--ids-space-4);
	}

	.status__icon {
		width: 44px;
		height: 44px;
	}
}
</style>
