<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { mdiAccountQuestionOutline, mdiMapMarkerOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { t } from '@nextcloud/l10n'
import { computed, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import ShowMore from '../../components/common/ShowMore.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import EventDetails from './EventDetails.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError, errorMessage, isCancelled } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { APP_ID } from '../../utils/format.ts'
import { confirmEvent, denyEvent, isRefusedFromThisSession } from '../api.ts'
import { personal, refreshOverview } from '../store.ts'

/** An open "Was this you?" question, with its answers */
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

const busy = ref<'confirm' | 'deny' | null>(null)
const denyDialog = ref(false)
/** The server refused "Yes" from this session, although the list allowed it */
const refused = ref(false)
const canConfirm = computed(() => props.event.canConfirm && !refused.value)

/**
 * "Yes, it was me", after the password.
 */
async function confirm() {
	busy.value = 'confirm'
	try {
		const event = await confirmEvent(props.event.id)
		announce(t(APP_ID, 'Thank you. You confirmed that it was you.'))
		showSuccess(t(APP_ID, 'Thank you. The network of this event is now trusted for a while.'))
		personal.networksVersion++
		personal.manage.networks = Math.max(personal.manage.networks, 1)
		emit('answered', event)
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
		announce(t(APP_ID, 'Thank you. Your answer was recorded and your administrators were told.'))
		showSuccess(t(APP_ID, 'Thank you. Your answer was recorded and your administrators were told.'))
		personal.networksVersion++
		emit('answered', event)
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
	<li :class="$style.event" :data-test="`event-${event.id}`">
		<div :class="$style.event__head">
			<span :class="$style.event__icon" aria-hidden="true">
				<NcIconSvgWrapper :path="mdiAccountQuestionOutline" :size="20" />
			</span>
			<div :class="$style.event__main">
				<h4 :id="`${id}-title`" :class="$style.event__title">
					{{ event.subject }}
				</h4>
				<p :class="$style.event__meta">
					<TimeStamp :timestamp="event.createdAt" :timeZone="timeZone" />
					<span v-if="event.address" :class="$style.event__address">
						<NcIconSvgWrapper inline :path="mdiMapMarkerOutline" :size="16" />
						<span class="hidden-visually">{{ t(APP_ID, 'From the address') }}</span>
						{{ event.address }}
					</span>
				</p>
			</div>
		</div>

		<div
			:class="$style.question"
			role="group"
			:aria-labelledby="`${id}-title`"
			data-test="question">
			<p :class="$style.question__text">
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

		<ShowMore :label="t(APP_ID, 'Details')" :class="$style.event__more" data-test="toggle">
			<EventDetails :event="event" />
		</ShowMore>

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
	gap: calc(var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 4);
	border: 1px solid color-mix(in srgb, var(--color-warning) 45%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.event__head {
	display: flex;
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
	background-color: color-mix(in srgb, var(--color-warning) 18%, var(--color-main-background));
	color: var(--color-warning-text);
}

.event__main {
	display: flex;
	flex: 1 1 auto;
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

.event__address {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
	font-variant-numeric: tabular-nums;
	overflow-wrap: anywhere;
}

.question,
.event__more {
	margin-inline-start: calc(36px + var(--default-grid-baseline) * 3);
}

.question {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.question__text,
.question__note {
	margin: 0;
	max-width: 75ch;
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

.dialog {
	margin: 0 0 calc(var(--default-grid-baseline) * 2);
	line-height: 1.5;
}

@media (max-width: 480px) {
	.event {
		padding: calc(var(--default-grid-baseline) * 3);
	}

	.question,
	.event__more {
		margin-inline-start: 0;
	}
}
</style>
