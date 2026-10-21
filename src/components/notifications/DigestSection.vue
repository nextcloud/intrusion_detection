<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { DigestOverview } from '../../types.ts'

import { mdiCalendarClockOutline, mdiEmailFastOutline } from '@mdi/js'
import { showError, showSuccess } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, onMounted, ref, watch } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import TimeStamp from '../common/TimeStamp.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, fetchDigest, isCancelled, sendTestDigest } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { state } from '../../store.ts'
import { APP_ID } from '../../utils/format.ts'

/** The settings this section edits */
const SETTINGS = ['digest_frequency']

const digest = ref<DigestOverview | null>(null)
const loadFailed = ref(false)
const sending = ref(false)
const { announce } = useAnnouncer()

const settings = computed(() => state.settings.filter((s) => SETTINGS.includes(s.name)))

const withoutEmailNames = computed(() => {
	const value = digest.value
	if (!value) {
		return ''
	}
	const names = value.withoutEmail.map((user) => user.displayName || user.uid)
	const more = value.withoutEmailCount - names.length
	return more > 0 ? t(APP_ID, '{names} and {count} more', { names: names.join(', '), count: more }, undefined, { escape: false, sanitize: false }) : names.join(', ')
})

const last = computed(() => {
	const value = digest.value?.last
	if (!value) {
		return null
	}
	switch (value.result) {
		case 'sent':
			return n(APP_ID, 'Sent to %n person.', 'Sent to %n people.', value.recipients)
		case 'quiet_skipped':
			return t(APP_ID, 'Nothing had happened, and quiet digests are off, so none was sent.')
		case 'no_recipients':
			return t(APP_ID, 'Nobody in the notification groups has an email address, so none was sent.')
		default:
			return t(APP_ID, 'It could not be sent. Check the email server settings and the server log.')
	}
})

const recipients = computed(() => {
	const value = digest.value
	if (!value) {
		return ''
	}
	if (value.recipients === 0) {
		return t(APP_ID, 'Nobody in the notification groups has an email address, so nobody gets the digest.')
	}
	const goes = n(APP_ID, 'The digest goes to %n person in the notification groups.', 'The digest goes to %n people in the notification groups.', value.recipients)
	if (value.withoutEmailCount === 0) {
		return goes
	}
	return goes + ' ' + n(APP_ID, '{names} has no email address and gets none.', '{names} have no email address and get none.', value.withoutEmailCount, { names: withoutEmailNames.value }, { escape: false, sanitize: false })
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
	<SectionCard
		level="h4"
		:heading="t(APP_ID, 'Digest email')"
		:icon="mdiCalendarClockOutline"
		data-test="digest-section">
		<template #description>
			{{ t(APP_ID, 'A regular summary for the administrators: how each check did, the most active addresses, and what is still open.') }}
		</template>

		<SettingsGroup v-if="settings.length > 0" :settings="settings" />

		<SkeletonBlock v-if="!digest && !loadFailed" height="72px" />
		<NcNoteCard v-else-if="loadFailed" type="error" :text="t(APP_ID, 'Who gets the digest could not be loaded. Please reload the page.')" />
		<template v-else-if="digest">
			<ul :class="$style.facts">
				<li data-test="digest-schedule">
					<template v-if="digest.frequency === 'off' || digest.nextDue === null">
						{{ t(APP_ID, 'The digest is off. Administrators still get notifications and emails about severe detections.') }}
					</template>
					<template v-else>
						<strong>{{ t(APP_ID, 'Next digest:') }}</strong>
						<TimeStamp :timestamp="digest.nextDue" :timeZone="digest.timezone" />
						<span :class="$style.muted">({{ digest.timezone }})</span>
					</template>
				</li>
				<li v-if="digest.last" data-test="digest-last">
					<strong>{{ t(APP_ID, 'Last digest:') }}</strong>
					<TimeStamp :timestamp="digest.last.sentAt" :timeZone="digest.timezone" />.
					{{ last }}
				</li>
				<li data-test="digest-recipients">
					{{ recipients }}
				</li>
			</ul>

			<div :class="$style.row">
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
				<p id="ids-digest-test-hint" :class="$style.hint">
					{{ digest.viewerHasEmail
						? t(APP_ID, 'Only you get it, marked as a test. It does not replace the next digest.')
						: t(APP_ID, 'Add an email address to your account in your personal settings to get a test digest.') }}
				</p>
			</div>
		</template>
	</SectionCard>
</template>

<style module>
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

.facts li > * + * {
	margin-inline-start: 0.3em;
}

.muted {
	color: var(--color-text-maxcontrast);
}

.row {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 3);
}

.hint {
	flex: 1 1 260px;
	margin: 0;
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}
</style>
