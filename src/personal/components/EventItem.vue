<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecurityEvent } from '../types.ts'

import { mdiAccountQuestionOutline, mdiMapMarkerOutline } from '@mdi/js'
import { computed, ref, useId } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import ShowMore from '../../components/common/ShowMore.vue'
import TimeStamp from '../../components/common/TimeStamp.vue'
import EventDetails from './EventDetails.vue'
import { useAction } from '../../composables/useAction.ts'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { ApiError } from '../../services/api.ts'
import { APP_ID } from '../../utils/format.ts'
import { t } from '../../utils/l10n.ts'
import { isRefusedFromThisSession } from '../api.ts'
import { answerEvent, personal } from '../store.ts'

/** An open "Was this you?" question, with its answers */
const props = defineProps<{
	event: SecurityEvent
}>()

const emit = defineEmits<{
	/** The event changed elsewhere; the list should be loaded again */
	stale: []
}>()

const id = useId()
const { announce } = useAnnouncer()
const timeZone = computed(() => personal.overview?.timezone)

const { busy, run } = useAction()
const denyDialog = ref(false)
/** Why "Yes" cannot be taken from this session, shown instead of sending it */
const yesDialog = ref(false)
/** The server refused "Yes" from this session, although the list allowed it */
const refused = ref(false)
/** "No" from a session that proved only the password: the administrators were told, the question stays open */
const toldOnly = ref(false)
const canConfirm = computed(() => props.event.canConfirm && !refused.value)

/**
 * "Yes, it was me", after the password.
 */
function confirm() {
	run('confirm', () => answerEvent(props.event.id, 'confirm'), {
		done: t(APP_ID, 'Thank you. The network of this event is now trusted for a while.'),
		toast: true,
		fallback: t(APP_ID, 'Your answer could not be saved. Please try again.'),
		handle: refusedOrStale,
	})
}

/**
 * "No, it was not me", after the dialog. From a session that proved only
 * the password, the administrators are told and the question stays open.
 */
function deny() {
	denyDialog.value = false
	run('deny', async () => {
		const event = await answerEvent(props.event.id, 'deny')
		toldOnly.value = event.verdict === null
		if (toldOnly.value) {
			announce(t(APP_ID, 'Your administrators were told. The question stays open.'))
		}
	}, {
		done: () => toldOnly.value ? '' : t(APP_ID, 'Thank you. Your answer was recorded and your administrators were told.'),
		toast: true,
		fallback: t(APP_ID, 'Your answer could not be saved. Please try again.'),
		handle: refusedOrStale,
	})
}

/**
 * A refused "Yes" opens the dialog that explains it. An answer the server
 * explained (answered elsewhere, no longer asked) loads the list again.
 *
 * @param error - What an answer threw
 * @return whether the refusal was shown
 */
function refusedOrStale(error: unknown): boolean {
	if (isRefusedFromThisSession(error)) {
		refused.value = true
		yesDialog.value = true
		return true
	}
	if (error instanceof ApiError) {
		emit('stale')
	}
	return false
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
					variant="secondary"
					:disabled="busy !== null"
					data-test="confirm"
					@click="canConfirm ? confirm() : (yesDialog = true)">
					<template v-if="busy === 'confirm'" #icon>
						<NcLoadingIcon :size="20" />
					</template>
					{{ t(APP_ID, 'Yes, it was me') }}
				</NcButton>
				<NcButton
					v-if="!toldOnly"
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
			<p v-if="toldOnly" :class="$style.question__note" data-test="told-only">
				{{ t(APP_ID, 'Your administrators were told. To end the sessions of this event, answer "No" again after a login with your second factor or an email code, or from a device you remembered.') }}
			</p>
		</div>

		<ShowMore :label="t(APP_ID, 'Details')" :class="$style.event__more" data-test="toggle">
			<EventDetails :event="event" />
		</ShowMore>

		<NcDialog
			v-model:open="yesDialog"
			:name="t(APP_ID, 'Answer “Yes” from a confirmed login')"
			:buttons="[{ label: t(APP_ID, 'OK'), variant: 'primary', callback: () => undefined }]"
			size="normal"
			data-test="confirm-elsewhere">
			<p :class="$style.dialog">
				{{ t(APP_ID, 'For your safety, "Yes, it was me" needs a login with your second factor, a confirmed login, or a remembered device, and not the session this event is about. Someone who knows only your password must not be able to answer for you.') }}
			</p>
			<p :class="$style.dialog">
				{{ t(APP_ID, 'Answer from another device where you logged in that way, or log in again with your second factor. The question stays open until then.') }}
			</p>
		</NcDialog>

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
	gap: var(--ids-space-3);
	padding: var(--ids-space-4);
	border: 1px solid color-mix(in srgb, var(--color-warning) 45%, var(--color-border));
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.event__head {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-3);
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
	gap: var(--ids-space-1);
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
	composes: muted from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-1) var(--ids-space-3);
	margin: 0;
	font-size: 0.92em;
}

.event__address {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-1);
	font-variant-numeric: tabular-nums;
	overflow-wrap: anywhere;
}

.question,
.event__more {
	margin-inline-start: calc(36px + var(--ids-space-3));
}

.question {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.question__text,
.question__note {
	margin: 0;
	max-width: 75ch;
	line-height: 1.5;
}

.question__note {
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.92em;
}

.question__buttons {
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.dialog {
	margin: 0 0 var(--ids-space-2);
	line-height: 1.5;
}

@media (max-width: 480px) {
	.event {
		padding: var(--ids-space-3);
	}

	.question,
	.event__more {
		margin-inline-start: 0;
	}
}
</style>
