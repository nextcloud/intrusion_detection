<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DetectionDetail } from '../../types.ts'

import { mdiAccountLockOpenOutline, mdiCheck, mdiKeyOutline } from '@mdi/js'
import { computed, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcProgressBar from '@nextcloud/vue/components/NcProgressBar'
import TimeStamp from '../common/TimeStamp.vue'
import { useAction } from '../../composables/useAction.ts'
import { confirmAccountPasswordReset, reenableLockedAccount, useAccountGuide } from '../../stores/overview.ts'
import { APP_ID } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const props = defineProps<{
	detail: DetectionDetail
}>()

const { data: guide } = useAccountGuide(() => props.detail.detection.id)
const { busy, error, run } = useAction()
const confirmReenable = ref(false)

const progress = computed(() => guide.value?.progress ?? null)
const percent = computed(() => progress.value && progress.value.total > 0 ? Math.round(progress.value.done / progress.value.total * 100) : 0)
const passwordWaits = computed(() => {
	const step = progress.value?.steps.find((s) => s.id === 'password')
	return progress.value?.active === true && step !== undefined && step.managed && !step.done
})
const shown = computed(() => guide.value !== null && (guide.value.lockedByLink || progress.value !== null))

const STEP_LABELS: Record<string, () => string> = {
	password: () => t(APP_ID, 'New password'),
	sessions: () => t(APP_ID, 'Devices checked'),
	two_factor: () => t(APP_ID, 'Two-factor authentication'),
	email: () => t(APP_ID, 'Email address checked'),
	shares: () => t(APP_ID, 'Shares checked'),
	files: () => t(APP_ID, 'Files checked'),
}

/**
 * @param action - The change
 * @param done - What to announce
 * @param fallback - What to say when it fails
 */
function change(action: (detectionId: number) => Promise<void>, done: string, fallback: string) {
	run('change', () => action(props.detail.detection.id), { done, fallback, inline: true })
}

const reenableButtons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{
		label: t(APP_ID, 'Enable the account'),
		variant: 'primary' as const,
		callback: () => {
			change(reenableLockedAccount, t(APP_ID, 'The account was enabled again.'), t(APP_ID, 'The account could not be enabled. Please try again.'))
		},
	},
])
</script>

<template>
	<section v-if="shown && guide" :class="$style.panel" :aria-label="t(APP_ID, 'Secure my account')">
		<h5 :class="$style.panel__heading">
			{{ t(APP_ID, 'Account of {user}', { user: guide.displayName }) }}
		</h5>
		<p v-if="guide.lockedByLink" :class="$style.panel__text">
			<template v-if="!guide.exists">
				{{ t(APP_ID, 'The account does not exist any more.') }}
			</template>
			<template v-else-if="guide.enabled">
				{{ t(APP_ID, 'The account is enabled again.') }}
			</template>
			<template v-else>
				{{ t(APP_ID, 'The account is locked: it is disabled, and every session and app password was ended. Talk to the user another way than by email before you enable it again, and check its email address in the account management.') }}
			</template>
		</p>

		<div v-if="progress" :class="$style.panel__progress">
			<span :class="$style.panel__count">
				{{ n(APP_ID, 'Secure my account: {done} of %n step done', 'Secure my account: {done} of %n steps done', progress.total, { done: progress.done }) }}
			</span>
			<NcProgressBar :value="percent" size="small" :aria-label="t(APP_ID, 'Progress of Secure my account')" />
			<span v-if="progress.startedAt" :class="$style.panel__muted">
				<template v-if="progress.active">{{ t(APP_ID, 'Started') }}</template>
				<template v-else-if="progress.closedBy === 'done'">{{ t(APP_ID, 'Finished') }}</template>
				<template v-else>{{ t(APP_ID, 'Closed by the user without finishing') }}</template>
				<TimeStamp :timestamp="progress.active ? progress.startedAt : (progress.closedAt ?? progress.startedAt)" />
			</span>
			<ul :class="$style.panel__steps">
				<li
					v-for="step in progress.steps.filter((s) => !s.skipped)"
					:key="step.id"
					:class="[$style.panel__step, step.done ? $style.panel__step_done : null]">
					<NcIconSvgWrapper v-if="step.done" :path="mdiCheck" :size="16" />
					{{ STEP_LABELS[step.id]?.() ?? step.id }}
					<span class="hidden-visually">{{ step.done ? t(APP_ID, 'done') : t(APP_ID, 'not done yet') }}</span>
				</li>
			</ul>
		</div>

		<NcNoteCard v-if="error" type="error" :text="error" />

		<div v-if="guide.canReenable || passwordWaits" :class="$style.panel__actions">
			<NcButton
				v-if="guide.canReenable"
				variant="primary"
				:disabled="busy !== null"
				@click="confirmReenable = true">
				<template #icon>
					<NcLoadingIcon v-if="busy !== null" :size="20" />
					<NcIconSvgWrapper v-else :path="mdiAccountLockOpenOutline" />
				</template>
				{{ t(APP_ID, 'Re-enable and start Secure my account') }}
			</NcButton>
			<NcButton
				v-if="passwordWaits"
				variant="secondary"
				:disabled="busy !== null"
				@click="change(confirmAccountPasswordReset, t(APP_ID, 'The password step is marked done.'), t(APP_ID, 'The step could not be marked. Please try again.'))">
				<template #icon>
					<NcIconSvgWrapper :path="mdiKeyOutline" />
				</template>
				{{ t(APP_ID, 'Password was reset in the directory') }}
			</NcButton>
		</div>

		<NcDialog
			v-model:open="confirmReenable"
			:name="t(APP_ID, 'Enable {user} again?', { user: guide.displayName })"
			:message="t(APP_ID, 'Only do this after you talked to the user another way than by email. They can log in again at once, and they are guided through securing their account.')"
			:buttons="reenableButtons"
			size="normal" />
	</section>
</template>

<style module>
.panel {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding: var(--ids-space-4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-primary-element) 6%, var(--color-main-background));
}

.panel__heading {
	margin: 0;
	font-size: 1em;
	font-weight: 600;
}

.panel__text {
	margin: 0;
	line-height: 1.5;
}

.panel__progress {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1-5);
	max-width: 520px;
}

.panel__count {
	font-weight: 600;
}

.panel__muted {
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-1);
	font-size: 0.9em;
}

.panel__steps {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-1-5);
}

.panel__step {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	padding-inline: var(--ids-space-2);
	border: 1px dashed var(--color-border-maxcontrast, var(--color-border));
	border-radius: var(--border-radius-element);
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	line-height: 24px;
}

.panel__step_done {
	border-style: solid;
	border-color: transparent;
	background-color: color-mix(in srgb, var(--color-success) 14%, var(--color-main-background));
	color: var(--color-success-text);
}

.panel__actions {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}
</style>
