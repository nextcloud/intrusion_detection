<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { mdiAccountQuestionOutline, mdiCheckCircleOutline, mdiChevronDown, mdiCloseCircleOutline, mdiInformationOutline, mdiMapMarkerOutline, mdiShieldCheckOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import StateBadge from '../../components/common/StateBadge.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError, errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { confirmEvent, denyEvent, isRefusedFromThisSession } from '../api.ts'
import { personal, refreshOverview } from '../store.ts'
import { dateTime } from '../time.ts'

const props = defineProps<{
	event: SecurityEvent
}>()

const emit = defineEmits<{
	/** The event with its answer */
	answered: [event: SecurityEvent]
	/** The event changed elsewhere; the list should be loaded again */
	stale: []
}>()

const id = useId()
const { announce } = useAnnouncer()
const timeZone = computed(() => personal.overview?.timezone)

const isOpen = computed(() => props.event.asks && props.event.verdict === null)
const expanded = ref(isOpen.value)
const busy = ref<'confirm' | 'deny' | null>(null)
const denyDialog = ref(false)
/** The server refused "Yes" from this session, although the list allowed it */
const refused = ref(false)
const canConfirm = computed(() => props.event.canConfirm && !refused.value)

const state = computed(() => {
	if (isOpen.value) {
		return { type: 'warning' as const, icon: mdiAccountQuestionOutline, label: t(APP_ID, 'Needs your answer') }
	}
	if (props.event.verdict === 'confirmed') {
		return { type: 'success' as const, icon: mdiCheckCircleOutline, label: t(APP_ID, 'You said it was you') }
	}
	if (props.event.verdict === 'denied') {
		return { type: 'info' as const, icon: mdiCloseCircleOutline, label: t(APP_ID, 'You said it was not you') }
	}
	return props.event.done.length > 0
		? { type: 'neutral' as const, icon: mdiShieldCheckOutline, label: t(APP_ID, 'Handled') }
		: { type: 'neutral' as const, icon: mdiInformationOutline, label: t(APP_ID, 'For your information') }
})

const answer = computed(() => {
	if (props.event.verdict === null || props.event.verdictAt === null) {
		return null
	}
	const at = dateTime(props.event.verdictAt, timeZone.value)
	return props.event.verdict === 'confirmed'
		? t(APP_ID, 'You answered "Yes, it was me" on {date}. Its network is trusted for a while.', { date: at })
		: t(APP_ID, 'You answered "No, it was not me" on {date}. Your administrators were told.', { date: at })
})

/**
 * "Yes, it was me", after the password.
 */
async function confirm() {
	busy.value = 'confirm'
	try {
		const event = await confirmEvent(props.event.id)
		emit('answered', event)
		announce(t(APP_ID, 'Thank you. You confirmed that it was you.'))
		showSuccess(t(APP_ID, 'Thank you. The network of this event is now trusted for a while.'))
		personal.networksVersion++
		refreshOverview()
	} catch (error) {
		failed(error)
	} finally {
		busy.value = null
	}
}

/**
 * "No, it was not me", after the dialog.
 */
async function deny() {
	denyDialog.value = false
	busy.value = 'deny'
	try {
		const event = await denyEvent(props.event.id)
		emit('answered', event)
		announce(t(APP_ID, 'Thank you. Your answer was recorded and your administrators were told.'))
		showSuccess(t(APP_ID, 'Thank you. Your answer was recorded and your administrators were told.'))
		personal.networksVersion++
		refreshOverview()
	} catch (error) {
		failed(error)
	} finally {
		busy.value = null
	}
}

/**
 * @param error - What an answer threw
 */
function failed(error: unknown) {
	if (isCancelled(error)) {
		return
	}
	if (isRefusedFromThisSession(error)) {
		refused.value = true
		announce(t(APP_ID, 'This answer cannot be given from this session.'))
		return
	}
	logger.error('Could not answer "Was this you?"', { error })
	const message = errorMessage(error, t(APP_ID, 'Your answer could not be saved. Please try again.'))
	showError(message)
	announce(message)
	if (error instanceof ApiError) {
		// Answered elsewhere already, or no longer asked.
		emit('stale')
	}
}

const denyButtons = computed(() => [
	{ label: t(APP_ID, 'Cancel'), callback: () => undefined },
	{ label: t(APP_ID, 'It was not me'), variant: 'error' as const, callback: () => { deny() } },
])
</script>

<template>
	<li :class="[$style.event, { [$style.event_open]: isOpen }]" :data-test="`event-${event.id}`">
		<div :class="$style.event__head">
			<span :class="[$style.event__icon, $style[`event__icon_${state.type}`]]" aria-hidden="true">
				<NcIconSvgWrapper :path="state.icon" :size="20" />
			</span>
			<div :class="$style.event__main">
				<h4 :id="`${id}-title`" :class="$style.event__title">
					{{ event.subject }}
				</h4>
				<p :class="$style.event__meta">
					<TimeStamp :timestamp="event.createdAt" :timeZone="timeZone" />
					<span :class="$style.event__absolute">{{ dateTime(event.createdAt, timeZone) }}</span>
					<span v-if="event.address" :class="$style.event__address">
						<NcIconSvgWrapper inline :path="mdiMapMarkerOutline" :size="16" />
						<span class="hidden-visually">{{ t(APP_ID, 'From the address') }}</span>
						{{ event.address }}
					</span>
				</p>
			</div>
			<StateBadge :type="state.type" :icon="state.icon" :class="$style.event__badge">
				{{ state.label }}
			</StateBadge>
		</div>

		<div
			v-if="isOpen"
			:class="$style.question"
			role="group"
			:aria-labelledby="`${id}-question`"
			data-test="question">
			<p :id="`${id}-question`" :class="$style.question__text">
				<strong>{{ t(APP_ID, 'Was this you?') }}</strong>
				{{ t(APP_ID, 'If you do not recognise it, say so: Nextcloud then ends the sessions that came with it.') }}
			</p>
			<div :class="$style.question__buttons">
				<NcButton
					v-if="canConfirm"
					variant="secondary"
					:disabled="busy !== null"
					data-test="confirm"
					@click="confirm">
					<template v-if="busy === 'confirm'" #icon>
						<NcLoadingIcon :size="20" />
					</template>
					{{ t(APP_ID, 'Yes, it was me') }}
				</NcButton>
				<NcButton
					variant="error"
					:disabled="busy !== null"
					data-test="deny"
					@click="denyDialog = true">
					<template v-if="busy === 'deny'" #icon>
						<NcLoadingIcon :size="20" />
					</template>
					{{ t(APP_ID, 'No, it was not me') }}
				</NcButton>
			</div>
			<p v-if="!canConfirm" :class="$style.question__note" data-test="confirm-elsewhere">
				{{ t(APP_ID, 'For your safety, "Yes, it was me" needs a login with your second factor, a confirmed login, or a remembered device, and not the session this event is about. Answer from another device.') }}
			</p>
		</div>
		<p v-else-if="answer" :class="$style.event__answer" data-test="answer">
			{{ answer }}
		</p>

		<NcButton
			variant="tertiary"
			:class="$style.event__toggle"
			:aria-expanded="expanded ? 'true' : 'false'"
			:aria-controls="`${id}-details`"
			data-test="toggle"
			@click="expanded = !expanded">
			<template #icon>
				<NcIconSvgWrapper :path="mdiChevronDown" :class="[$style.chevron, { [$style.chevron_open]: expanded }]" />
			</template>
			{{ expanded ? t(APP_ID, 'Hide details') : t(APP_ID, 'Show details') }}
		</NcButton>

		<Transition :enterFromClass="$style.details_hidden" :leaveToClass="$style.details_hidden">
			<div
				v-show="expanded"
				:id="`${id}-details`"
				:class="$style.details"
				data-test="details">
				<p v-for="(line, index) in event.happened" :key="`h${index}`">
					{{ line }}
				</p>
				<p :class="$style.details__when">
					{{ event.when }}
				</p>
				<template v-if="event.done.length > 0">
					<h5 :class="$style.details__heading">
						{{ t(APP_ID, 'What Nextcloud did') }}
					</h5>
					<ul :class="$style.details__list">
						<li v-for="(line, index) in event.done" :key="`d${index}`">
							{{ line }}
						</li>
					</ul>
				</template>
				<template v-if="event.advice.length > 0">
					<h5 :class="$style.details__heading">
						{{ t(APP_ID, 'What you can do') }}
					</h5>
					<ul :class="$style.details__list">
						<li v-for="(line, index) in event.advice" :key="`a${index}`">
							{{ line }}
						</li>
					</ul>
				</template>
			</div>
		</Transition>

		<NcDialog
			v-model:open="denyDialog"
			:name="t(APP_ID, 'This was not you?')"
			:buttons="denyButtons"
			size="normal">
			<p :class="$style.dialog">
				{{ t(APP_ID, 'Nextcloud will end the sessions and app passwords that came with this event, block the address it came from and tell your administrators. If your password was involved, you will choose a new one at your next login. After a login with only your password, only your administrators are told.') }}
			</p>
		</NcDialog>
	</li>
</template>

<style module>
.event {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.event_open {
	border-color: color-mix(in srgb, var(--color-warning) 45%, var(--color-border));
	box-shadow: inset 3px 0 0 var(--color-warning);
}

[dir='rtl'] .event_open {
	box-shadow: inset -3px 0 0 var(--color-warning);
}

.event__head {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.event__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: 36px;
	height: 36px;
	border-radius: 50%;
	background-color: var(--color-background-dark);
	color: var(--color-text-maxcontrast);
}

.event__icon_warning {
	background-color: color-mix(in srgb, var(--color-warning) 18%, var(--color-main-background));
	color: var(--color-warning-text);
}

.event__icon_success {
	background-color: color-mix(in srgb, var(--color-success) 16%, var(--color-main-background));
	color: var(--color-success-text);
}

.event__icon_info {
	background-color: color-mix(in srgb, var(--color-info) 16%, var(--color-main-background));
	color: var(--color-info-text);
}

.event__main {
	display: flex;
	flex: 1 1 260px;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	min-width: 0;
}

.event__title {
	margin: 0;
	font-size: 1em;
	font-weight: 600;
	line-height: 1.4;
	overflow-wrap: anywhere;
}

.event__meta {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1) calc(var(--default-grid-baseline) * 3);
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.event__absolute::before,
.event__address::before {
	content: '·';
	margin-inline-end: calc(var(--default-grid-baseline) * 3);
}

.event__address {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	font-variant-numeric: tabular-nums;
	overflow-wrap: anywhere;
}

.event__badge {
	margin-inline-start: auto;
}

.event__answer {
	margin: 0;
	padding-inline-start: calc(36px + var(--default-grid-baseline) * 3);
	color: var(--color-text-maxcontrast);
	line-height: 1.5;
}

.event__toggle {
	align-self: flex-start;
	margin-inline-start: calc(36px + var(--default-grid-baseline) * 1);
}

.chevron {
	transition: transform 150ms ease;
}

.chevron_open {
	transform: rotate(180deg);
}

.question {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	margin-inline-start: calc(36px + var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-large);
	background-color: color-mix(in srgb, var(--color-warning) 9%, var(--color-main-background));
}

.question__text,
.question__note {
	margin: 0;
	line-height: 1.5;
}

.question__note {
	color: var(--color-text-maxcontrast);
	font-size: 0.92em;
}

.question__buttons {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.details {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin-inline-start: calc(36px + var(--default-grid-baseline) * 3);
	padding-block-start: calc(var(--default-grid-baseline) * 1);
	line-height: 1.5;
	transition: opacity 180ms ease, transform 180ms ease;
}

.details p {
	margin: 0;
}

.details_hidden {
	opacity: 0;
	transform: translateY(-4px);
}

.details__when {
	color: var(--color-text-maxcontrast);
}

.details__heading {
	margin: calc(var(--default-grid-baseline) * 1) 0 0;
	font-size: 0.95em;
	font-weight: 600;
}

.details__list {
	margin: 0;
	padding-inline-start: calc(var(--default-grid-baseline) * 5);
	list-style: disc;
}

.dialog {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	line-height: 1.5;
}

@media (max-width: 480px) {
	.event {
		padding: calc(var(--default-grid-baseline) * 3);
	}

	.question,
	.details,
	.event__answer {
		margin-inline-start: 0;
		padding-inline-start: 0;
	}

	.question {
		padding-inline-start: calc(var(--default-grid-baseline) * 3);
	}

	.event__toggle {
		margin-inline-start: 0;
	}

	.event__badge {
		margin-inline-start: 0;
	}

	.event__main {
		flex-basis: 180px;
	}

	.event__meta {
		flex-direction: column;
		align-items: flex-start;
	}

	.event__absolute::before,
	.event__address::before {
		content: none;
	}
}

@media (prefers-reduced-motion: reduce) {
	.chevron,
	.details {
		transition: none;
	}
}
</style>
