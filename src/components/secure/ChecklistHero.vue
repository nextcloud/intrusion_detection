<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecureAccountProgress } from '../../secureAccountTypes.ts'

import { mdiShieldAccountOutline, mdiShieldCheckOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import { APP_ID } from '../../utils/format.ts'

/** The top of "Secure my account": why, how far, and starting it */
const props = defineProps<{
	progress: SecureAccountProgress
	/** Every step of a closed checklist is done */
	finished: boolean
	/** The checklist is being started */
	starting: boolean
	disabled: boolean
}>()

const emit = defineEmits<{
	start: []
}>()

const applicable = computed(() => props.progress.steps.filter((step) => !step.skipped))

const lead = computed(() => {
	switch (props.progress.reason) {
		case 'reenabled':
			return t(APP_ID, 'Your administrator enabled your account again after it was locked. Go through these steps to make sure nobody else can get in.')
		case 'denied':
			return t(APP_ID, 'You said that something on your account was not you. Nextcloud already ended the sessions involved. Go through these steps to make sure nobody else can get in.')
		case 'detection':
			return t(APP_ID, 'Nextcloud noticed signs that someone else may have had your password. Go through these steps to make sure nobody else can get in.')
		default:
			return t(APP_ID, 'Go through these steps to make sure nobody else can get into your account.')
	}
})
</script>

<template>
	<header :class="[$style.hero, finished ? $style.hero_done : null]">
		<span :class="$style.hero__icon" aria-hidden="true">
			<NcIconSvgWrapper :path="finished ? mdiShieldCheckOutline : mdiShieldAccountOutline" :size="32" />
		</span>
		<div :class="$style.hero__text">
			<h2 :class="$style.hero__title">
				{{ t(APP_ID, 'Secure my account') }}
			</h2>
			<p v-if="progress.active" :class="$style.hero__lead">
				{{ lead }}
			</p>
			<p v-else-if="finished" :class="$style.hero__lead">
				{{ t(APP_ID, 'All done. Your account is as safe as you can make it. Thank you for checking.') }}
			</p>
			<p v-else :class="$style.hero__lead">
				{{ t(APP_ID, 'If you think someone else got into your account, this checklist guides you through securing it: a new password, your devices, two-factor authentication, your email address and what you shared.') }}
			</p>
			<div v-if="progress.active || finished" :class="$style.hero__progress">
				<span :class="$style.hero__count">
					{{ n(APP_ID, '{done} of %n step done', '{done} of %n steps done', progress.total, { done: progress.done }) }}
				</span>
				<span
					:class="$style.hero__bar"
					role="progressbar"
					:aria-label="t(APP_ID, 'Progress of the checklist')"
					aria-valuemin="0"
					:aria-valuemax="progress.total"
					:aria-valuenow="progress.done"
					data-test="checklist-progress">
					<span
						v-for="step in applicable"
						:key="step.id"
						:class="[$style.hero__segment, { [$style.hero__segment_done]: step.done }]" />
				</span>
			</div>
		</div>
		<div v-if="!progress.active" :class="$style.hero__actions">
			<NcButton variant="primary" :disabled="disabled" @click="emit('start')">
				<template #icon>
					<NcLoadingIcon v-if="starting" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiShieldAccountOutline" />
				</template>
				{{ finished ? t(APP_ID, 'Go through it again') : t(APP_ID, 'Start the checklist') }}
			</NcButton>
		</div>
	</header>
</template>

<style module>
.hero {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: var(--ids-space-5);
	padding: var(--ids-space-6);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-container, var(--border-radius-large));
	background-color: color-mix(in srgb, var(--color-primary-element) 8%, var(--color-main-background));
}

.hero_done {
	background-color: color-mix(in srgb, var(--color-success) 12%, var(--color-main-background));
}

.hero__icon {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	flex: 0 0 auto;
	width: 56px;
	height: 56px;
	border-radius: 50%;
	background-color: var(--color-main-background);
	color: var(--color-primary-element);
}

.hero_done .hero__icon {
	color: var(--color-success-text);
}

.hero__text {
	display: flex;
	flex: 1 1 320px;
	flex-direction: column;
	gap: var(--ids-space-2);
	min-width: 0;
}

.hero__title {
	margin: 0;
	font-size: 1.6em;
	line-height: 1.25;
}

.hero__lead {
	margin: 0;
	max-width: 60ch;
	line-height: 1.5;
}

.hero__progress {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1-5);
	max-width: 420px;
	margin-block-start: var(--ids-space-2);
}

.hero__count {
	font-weight: 600;
}

.hero__bar {
	display: flex;
	gap: var(--ids-space-1);
}

.hero__segment {
	flex: 1 1 0;
	height: 8px;
	border-radius: 4px;
	background-color: color-mix(in srgb, var(--color-main-text) 14%, var(--color-main-background));
}

.hero__segment_done {
	background-color: var(--color-success);
}

.hero__actions {
	display: flex;
	align-items: center;
}

@media (max-width: 600px) {
	.hero {
		padding: var(--ids-space-4);
	}
}
</style>
