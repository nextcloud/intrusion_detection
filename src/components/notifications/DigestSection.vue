<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DigestOverview } from '../../types.ts'

import { mdiCalendarClockOutline, mdiEmailFastOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { getCanonicalLocale, n, t } from '@nextcloud/l10n'
import { generateUrl } from '@nextcloud/router'
import { computed, onMounted, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SettingsGroup from '../common/SettingsGroup.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, fetchDigest, isCancelled, sendTestDigest } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

/** The settings this section edits */
const SETTINGS = ['digest_frequency', 'digest_send_quiet']

const digest = ref<DigestOverview | null>(null)
const loadFailed = ref(false)
const sending = ref(false)
const { announce } = useAnnouncer()

const settings = computed(() => state.settings.filter((s) => SETTINGS.includes(s.name)))
const mailSettingsUrl = generateUrl('/settings/admin/server')

/**
 * @param timestamp - Unix time
 */
function formatTime(timestamp: number): string {
	return new Date(timestamp * 1000).toLocaleString(getCanonicalLocale(), {
		dateStyle: 'full',
		timeStyle: 'short',
		timeZone: digest.value?.timezone,
	})
}

const schedule = computed(() => {
	const value = digest.value
	if (!value || value.frequency === 'off' || value.nextDue === null) {
		return t(APP_ID, 'The digest is off. Administrators still get notifications and emails about severe detections.')
	}
	return t(APP_ID, 'Next digest: {time} ({timezone}).', { time: formatTime(value.nextDue), timezone: value.timezone })
})

const last = computed(() => {
	const value = digest.value?.last
	if (!value) {
		return null
	}
	const time = formatTime(value.sentAt)
	switch (value.result) {
		case 'sent':
			return n(APP_ID, 'Last digest: {time}, sent to %n person.', 'Last digest: {time}, sent to %n people.', value.recipients, { time })
		case 'quiet_skipped':
			return t(APP_ID, 'Last digest: {time}. Nothing had happened, and quiet digests are off, so none was sent.', { time })
		case 'no_recipients':
			return t(APP_ID, 'Last digest: {time}. Nobody in the notification groups has an email address, so none was sent.', { time })
		default:
			return t(APP_ID, 'Last digest: {time}. It could not be sent. Check the email server settings and the server log.', { time })
	}
})

const recipients = computed(() => {
	const value = digest.value
	if (!value) {
		return ''
	}
	return value.recipients === 0
		? t(APP_ID, 'Nobody in the notification groups has an email address, so nobody gets the digest.')
		: n(APP_ID, 'The digest goes to %n person in the notification groups.', 'The digest goes to %n people in the notification groups.', value.recipients)
})

const withoutEmailNames = computed(() => {
	const value = digest.value
	if (!value) {
		return ''
	}
	const names = value.withoutEmail.map((user) => user.displayName || user.uid)
	const more = value.withoutEmailCount - names.length
	return more > 0 ? t(APP_ID, '{names} and {count} more', { names: names.join(', '), count: more }) : names.join(', ')
})

/**
 * Load who gets the digest and when.
 */
async function load() {
	try {
		digest.value = await fetchDigest()
		loadFailed.value = false
	} catch (error) {
		logger.error('Could not load the digest settings', { error })
		loadFailed.value = true
	}
}

/**
 * Send the digest of the period up to now to the current admin only.
 */
async function sendTest() {
	sending.value = true
	try {
		const { message } = await sendTestDigest()
		showSuccess(message)
		announce(message)
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not send a test digest', { error })
			const message = errorMessage(error, t(APP_ID, 'The test digest could not be sent. Please try again.'))
			showError(message)
			announce(message)
		}
	} finally {
		sending.value = false
	}
}

// When to send changes with the settings, so the schedule is loaded again after a save.
watch(() => settings.value.map((s) => s.value).join('|'), load)
onMounted(load)
</script>

<template>
	<section :class="$style.card" aria-labelledby="ids-digest-heading" data-test="digest-section">
		<div :class="$style.card__header">
			<span :class="$style.card__icon" aria-hidden="true">
				<NcIconSvgWrapper :path="mdiCalendarClockOutline" />
			</span>
			<div>
				<h3 id="ids-digest-heading" :class="$style.card__heading">
					{{ t(APP_ID, 'Digest email') }}
				</h3>
				<p :class="$style.card__text">
					{{ t(APP_ID, 'A summary for the administrators: the state of protection, every check this period compared with the one before, the most active addresses, accounts and shares under attack, decoys that were used, blocklist matches and open items.') }}
				</p>
			</div>
		</div>

		<SettingsGroup v-if="settings.length > 0" :settings="settings" />

		<SkeletonBlock v-if="!digest && !loadFailed" height="72px" />
		<NcNoteCard v-else-if="loadFailed" type="error" :text="t(APP_ID, 'Who gets the digest could not be loaded. Please reload the page.')" />
		<template v-else-if="digest">
			<NcNoteCard v-if="!digest.mailConfigured" type="warning">
				{{ t(APP_ID, 'No email server is set up, so no digest can be sent.') }}
				<a :href="mailSettingsUrl" :class="$style.link">{{ t(APP_ID, 'Set up the email server') }}</a>
			</NcNoteCard>

			<ul :class="$style.facts">
				<li data-test="digest-schedule">
					{{ schedule }}
				</li>
				<li v-if="last" data-test="digest-last">
					{{ last }}
				</li>
				<li data-test="digest-recipients">
					{{ recipients }}
				</li>
			</ul>

			<NcNoteCard v-if="digest.withoutEmailCount > 0" type="info" data-test="digest-without-email">
				<p :class="$style.note">
					{{ n(APP_ID, '%n person in the notification groups has no email address and gets no digest: {names}.', '%n people in the notification groups have no email address and get no digest: {names}.', digest.withoutEmailCount, { names: withoutEmailNames }) }}
				</p>
				<p :class="$style.note">
					{{ t(APP_ID, 'They still get the notifications in Nextcloud and see everything on this page.') }}
				</p>
			</NcNoteCard>

			<div :class="$style.card__row">
				<NcButton
					variant="secondary"
					:disabled="sending || !digest.viewerHasEmail"
					aria-describedby="ids-digest-test-hint"
					@click="sendTest">
					<template #icon>
						<NcLoadingIcon v-if="sending" />
						<NcIconSvgWrapper v-else :path="mdiEmailFastOutline" />
					</template>
					{{ t(APP_ID, 'Send a test digest now') }}
				</NcButton>
				<p id="ids-digest-test-hint" :class="$style.card__hint">
					{{ digest.viewerHasEmail
						? t(APP_ID, 'Only you get it, marked as a test. It covers the period up to now and does not replace the next digest.')
						: t(APP_ID, 'Add an email address to your account in your personal settings to get a test digest.') }}
				</p>
			</div>
		</template>
	</section>
</template>

<style module>
.card {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	min-width: 0;
	padding: calc(var(--default-grid-baseline) * 5);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-large);
	background-color: var(--color-main-background);
}

.card__header {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__icon {
	display: inline-flex;
	flex: 0 0 auto;
	align-items: center;
	justify-content: center;
	width: calc(var(--default-grid-baseline) * 10);
	height: calc(var(--default-grid-baseline) * 10);
	border-radius: 50%;
	background-color: var(--color-primary-element-light);
	color: var(--color-primary-element-light-text);
}

.card__heading {
	margin: 0;
	font-size: 1.15em;
	font-weight: 700;
}

.card__text {
	margin-block: calc(var(--default-grid-baseline) * 1) 0;
	max-width: 75ch;
	line-height: 1.6;
}

.facts {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 3) calc(var(--default-grid-baseline) * 4);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	list-style: none;
	line-height: 1.5;
}

.note {
	margin: 0;
}

.note + .note {
	margin-block-start: calc(var(--default-grid-baseline) * 1);
}

.link {
	margin-inline-start: calc(var(--default-grid-baseline) * 1);
	text-decoration: underline;
}

.card__row {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
}

.card__hint {
	flex: 1 1 260px;
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

@media (max-width: 600px) {
	.card {
		padding: calc(var(--default-grid-baseline) * 3);
	}
}
</style>
