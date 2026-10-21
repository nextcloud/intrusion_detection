<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Notifications, TestAlertResult } from '../../types.ts'

import { mdiAccountGroupOutline, mdiAlertCircleOutline, mdiBellOutline, mdiCheck, mdiCheckCircleOutline, mdiEmailOffOutline, mdiEmailOutline, mdiFormatListChecks, mdiMinus } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { generateUrl } from '@nextcloud/router'
import { computed, onActivated, onMounted, ref, watch } from 'vue'
import NcAvatar from '@nextcloud/vue/components/NcAvatar'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcSettingsSelectGroup from '@nextcloud/vue/components/NcSettingsSelectGroup'
import LiveSentence from '../checks/LiveSentence.vue'
import SectionCard from '../common/SectionCard.vue'
import SelectField from '../common/SelectField.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import StateBadge from '../common/StateBadge.vue'
import DigestSection from '../notifications/DigestSection.vue'
import WebhookEventsSection from '../notifications/WebhookEventsSection.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, fetchNotifications, isCancelled, sendTestAlert, updateSettings } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { refreshChecks, state } from '../../store.ts'
import { APP_ID, fillTemplate } from '../../utils/format.ts'

const data = ref<Notifications | null>(null)
const loadError = ref<string | null>(null)
const groups = ref<string[]>([])
const severity = ref('high')
const saving = ref(false)
const testing = ref(false)
const testResult = ref<TestAlertResult | null>(null)
const { announce } = useAnnouncer()
const mailSettingsUrl = generateUrl('/settings/admin/server')

const savedGroups = computed<string[]>(() => {
	const value = state.settings.find((s) => s.name === 'notify_admin_group')?.value
	return Array.isArray(value) ? value : []
})
const savedSeverity = computed(() => String(state.settings.find((s) => s.name === 'notify_admin_email_min_severity')?.value ?? 'high'))

watch(savedGroups, (value) => {
	groups.value = [...value]
}, { immediate: true })
watch(savedSeverity, (value) => {
	severity.value = value
}, { immediate: true })

const dirty = computed(() => severity.value !== savedSeverity.value
	|| groups.value.length !== savedGroups.value.length
	|| groups.value.some((g) => !savedGroups.value.includes(g)))

const SEVERITIES = [
	{ value: 'low', label: () => t(APP_ID, 'Every detection') },
	{ value: 'medium', label: () => t(APP_ID, 'Medium and above') },
	{ value: 'high', label: () => t(APP_ID, 'High and above') },
	{ value: 'critical', label: () => t(APP_ID, 'Critical only') },
	{ value: 'never', label: () => t(APP_ID, 'Never') },
]

const emailSentence = computed(() => {
	const label = { low: t(APP_ID, 'every severity'), medium: t(APP_ID, 'Medium'), high: t(APP_ID, 'High'), critical: t(APP_ID, 'Critical') }[severity.value]
	if (label === undefined) {
		return [{ text: t(APP_ID, 'No emails are sent. Alerts appear only as notifications in Nextcloud.') }]
	}
	const template = severity.value === 'low'
		? t(APP_ID, 'Every detection with a notification is also emailed, at most once per check and hour.')
		: t(APP_ID, 'Detections of severity {severity} or higher are also emailed, at most once per check and hour. The others appear only as notifications in Nextcloud.')
	return fillTemplate(template, { severity: label })
})

const notifying = computed(() => data.value?.checks.filter((c) => c.admin).length ?? 0)

/**
 * Load who is notified.
 */
async function load() {
	try {
		data.value = await fetchNotifications()
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the notifications', { error })
		loadError.value = errorMessage(error, t(APP_ID, 'The notification settings could not be loaded. Please reload the page.'))
	}
}

onMounted(load)
onActivated(load)

/**
 * Save the groups and the email severity.
 */
async function save() {
	saving.value = true
	try {
		const payload = await updateSettings({ notify_admin_group: groups.value, notify_admin_email_min_severity: severity.value })
		state.settings = payload.settings
		state.templates = payload.templates
		await load()
		announce(t(APP_ID, 'Saved'))
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the notification settings', { error })
			showError(errorMessage(error, t(APP_ID, 'The settings could not be saved. Please try again.')))
		}
	} finally {
		saving.value = false
	}
}

/**
 * Send the test alert.
 */
async function test() {
	testing.value = true
	try {
		testResult.value = await sendTestAlert()
		announce(t(APP_ID, 'The test alert was sent. Look at the notifications at the top right.'))
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not send the test alert', { error })
			showError(errorMessage(error, t(APP_ID, 'The test alert could not be sent. Please try again in a few minutes.')))
		}
	} finally {
		testing.value = false
	}
}

const emailResult = computed(() => {
	const result = testResult.value
	if (result === null) {
		return null
	}
	return {
		sent: { ok: true, text: t(APP_ID, 'Email sent to {address}. It can take a minute to arrive.', { address: result.address ?? '' }, undefined, { escape: false, sanitize: false }) },
		no_address: { ok: false, text: t(APP_ID, 'No email: your account has no email address. Add one in your personal settings.') },
		no_mail: { ok: false, text: t(APP_ID, 'No email: this server cannot send emails yet. Set up email in the basic settings.') },
		failed: { ok: false, text: t(APP_ID, 'The email could not be sent. The server log has the details.') },
	}[result.email]
})

/**
 * Keep the check cards in step when someone opens one from here.
 */
function openCheck() {
	refreshChecks().catch((error) => logger.error('Could not reload the checks', { error }))
}
</script>

<template>
	<div :class="$style.stack">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock v-for="i in 3" :key="i" height="140px" />
		</div>

		<template v-else>
			<NcNoteCard v-if="!data.mail" type="warning" data-test="no-mail">
				{{ t(APP_ID, 'This server cannot send emails yet, so alerts and digests appear only inside Nextcloud.') }}
				<a :href="mailSettingsUrl" :class="$style.link">{{ t(APP_ID, 'Set up the email server') }}</a>
			</NcNoteCard>

			<SectionCard level="h4" :heading="t(APP_ID, 'Who is notified')" :icon="mdiAccountGroupOutline">
				<template #description>
					{{ t(APP_ID, 'Members of these groups get the administrator alerts, at most one per check, address and hour.') }}
				</template>
				<form :class="$style.form" @submit.prevent="save">
					<div :class="$style.field">
						<span id="ids-notify-groups" :class="$style.field__label">{{ t(APP_ID, 'Notify these groups') }}</span>
						<NcSettingsSelectGroup
							v-model="groups"
							:label="t(APP_ID, 'Notify these groups')"
							:placeholder="t(APP_ID, 'Choose groups')"
							:disabled="saving"
							aria-labelledby="ids-notify-groups" />
					</div>

					<div :class="$style.field">
						<SelectField
							v-model="severity"
							:class="$style.field__select"
							:label="t(APP_ID, 'Also send an email for')"
							:options="SEVERITIES.map((option) => ({ value: option.value, label: option.label() }))"
							:disabled="saving" />
						<p :class="$style.field__sentence">
							<LiveSentence :segments="emailSentence" :changed="severity !== savedSeverity ? ['severity'] : []" />
						</p>
					</div>

					<div v-if="dirty" :class="$style.form__save">
						<NcButton type="submit" variant="primary" :disabled="saving || groups.length === 0">
							<template v-if="saving" #icon>
								<NcLoadingIcon />
							</template>
							{{ t(APP_ID, 'Save changes') }}
						</NcButton>
						<NcButton variant="tertiary" :disabled="saving" @click="groups = [...savedGroups]; severity = savedSeverity">
							{{ t(APP_ID, 'Discard') }}
						</NcButton>
						<span v-if="groups.length === 0" :class="$style.error">{{ t(APP_ID, 'Choose at least one group.') }}</span>
					</div>
				</form>

				<div :class="$style.people">
					<p :class="$style.people__count">
						{{ n(APP_ID, '%n person gets these alerts now:', '%n people get these alerts now:', data.recipients.length) }}
					</p>
					<ul :class="$style.people__list">
						<li v-for="person in data.recipients" :key="person.uid" :class="$style.person">
							<NcAvatar
								:user="person.uid"
								:displayName="person.displayName"
								:size="28"
								disableMenu
								disableTooltip />
							<span :class="$style.person__name">{{ person.displayName }}</span>
							<NcIconSvgWrapper
								inline
								:class="person.hasEmail ? $style.person__mail : $style.person__nomail"
								:path="person.hasEmail ? mdiEmailOutline : mdiEmailOffOutline"
								:size="16"
								:name="person.hasEmail ? t(APP_ID, 'has an email address') : t(APP_ID, 'no email address')" />
							<span v-if="!person.hasEmail" :class="$style.person__note" aria-hidden="true">{{ t(APP_ID, 'no email') }}</span>
						</li>
					</ul>
					<p v-if="data.recipients.length >= data.recipientLimit" :class="$style.muted">
						{{ n(APP_ID, 'At most %n person is notified, so one alert cannot become a flood.', 'At most %n people are notified, so one alert cannot become a flood.', data.recipientLimit) }}
					</p>
					<NcNoteCard v-if="data.recipients.length === 0" type="warning">
						{{ t(APP_ID, 'Nobody is in these groups, so nobody is told about attacks. Choose a group with at least one active administrator.') }}
					</NcNoteCard>
				</div>
				<div :class="$style.test">
					<NcNoteCard v-if="!data.me.recipient" type="info">
						{{ t(APP_ID, 'You are not in the groups above, so real alerts do not reach you. The test is still sent to you.') }}
					</NcNoteCard>
					<div>
						<NcButton variant="secondary" :disabled="testing" @click="test">
							<template #icon>
								<NcLoadingIcon v-if="testing" />
								<NcIconSvgWrapper v-else :path="mdiBellOutline" />
							</template>
							{{ t(APP_ID, 'Send a test alert to me') }}
						</NcButton>
					</div>
					<ul
						v-if="testResult && emailResult"
						:class="$style.results"
						aria-live="polite"
						data-test="test-result">
						<li :class="$style.result">
							<NcIconSvgWrapper
								inline
								:class="$style.result_ok"
								:path="mdiCheckCircleOutline"
								:size="20" />
							<span>{{ t(APP_ID, 'Notification sent. Look at the bell at the top right.') }}</span>
						</li>
						<li :class="$style.result">
							<NcIconSvgWrapper
								inline
								:class="emailResult.ok ? $style.result_ok : $style.result_bad"
								:path="emailResult.ok ? mdiCheckCircleOutline : mdiAlertCircleOutline"
								:size="20" />
							<span>{{ emailResult.text }}</span>
						</li>
					</ul>
				</div>
			</SectionCard>

			<DigestSection />

			<SectionCard
				level="h4"
				:heading="t(APP_ID, 'Notifications per check')"
				:icon="mdiFormatListChecks"
				data-test="per-check">
				<template #description>
					{{ n(APP_ID, '%n check notifies the administrators.', '%n checks notify the administrators.', notifying) }}
					{{ t(APP_ID, 'Change this with the responses of each check.') }}
				</template>
				<ShowMore :label="t(APP_ID, 'Show each check')" data-test="per-check-toggle">
					<div :class="$style.tableWrap">
						<table :class="$style.table">
							<thead>
								<tr>
									<th scope="col">
										{{ t(APP_ID, 'Check') }}
									</th>
									<th scope="col">
										{{ t(APP_ID, 'Administrators') }}
									</th>
									<th scope="col">
										{{ t(APP_ID, 'Affected user') }}
									</th>
								</tr>
							</thead>
							<tbody>
								<tr v-for="check in data.checks" :key="check.id" :class="{ [$style.row_off]: check.mode === 'off' }">
									<th scope="row">
										<a :href="`#checks/${check.id}`" :class="$style.checkLink" @click="openCheck">{{ check.name }}</a>
										<StateBadge v-if="check.mode === 'off'">
											{{ t(APP_ID, 'Off') }}
										</StateBadge>
									</th>
									<td :data-label="t(APP_ID, 'Administrators')">
										<span v-if="!check.adminAvailable" :class="$style.muted" :title="t(APP_ID, 'This check has no such response')">
											<span aria-hidden="true">—</span>
											<span class="hidden-visually">{{ t(APP_ID, 'This check has no such response') }}</span>
										</span>
										<span v-else :class="check.admin ? $style.yes : $style.no">
											<NcIconSvgWrapper inline :path="check.admin ? mdiCheck : mdiMinus" :size="18" />
											{{ check.admin ? t(APP_ID, 'Notified') : t(APP_ID, 'Not notified') }}
										</span>
									</td>
									<td :data-label="t(APP_ID, 'Affected user')">
										<span v-if="!check.userAvailable" :class="$style.muted" :title="t(APP_ID, 'This check has no such response')">
											<span aria-hidden="true">—</span>
											<span class="hidden-visually">{{ t(APP_ID, 'This check has no such response') }}</span>
										</span>
										<span v-else :class="check.user ? $style.yes : $style.no">
											<NcIconSvgWrapper inline :path="check.user ? mdiCheck : mdiMinus" :size="18" />
											{{ check.user ? t(APP_ID, 'Notified') : t(APP_ID, 'Not notified') }}
										</span>
									</td>
								</tr>
							</tbody>
						</table>
					</div>
				</ShowMore>
			</SectionCard>

			<WebhookEventsSection />
		</template>
	</div>
</template>

<style module>
.stack {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.test {
	display: flex;
	flex-direction: column;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.form {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
}

.form__save {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
}

.field {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
}

.field__label {
	font-weight: 600;
}

.field__select {
	max-width: 300px;
	margin: 0;
}

.field__sentence {
	margin: 0;
	line-height: 1.6;
}

.error {
	color: var(--color-error-text);
	font-weight: 600;
}

.muted {
	color: var(--color-text-maxcontrast);
}

.people {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.people__count {
	margin: 0;
	font-weight: 600;
}

.people__list {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: 0;
	list-style: none;
}

.person {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-block: 2px;
	padding-inline: 2px calc(var(--default-grid-baseline) * 3);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-pill, 100px);
}

.person__name {
	font-weight: 600;
}

.person__mail {
	color: var(--color-text-maxcontrast);
}

.person__nomail {
	color: var(--color-warning-text);
}

.person__note {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
}

.results {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
	list-style: none;
}

.result {
	display: flex;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 2);
	line-height: 1.45;
}

.result > :first-child {
	flex: 0 0 auto;
}

.result_ok {
	color: var(--color-success-text);
}

.result_bad {
	color: var(--color-warning-text);
}

.tableWrap {
	overflow-x: auto;
}

.table {
	width: 100%;
	border-collapse: collapse;
}

.table th,
.table td {
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-bottom: 1px solid var(--color-border);
	text-align: start;
	vertical-align: middle;
}

.table thead th {
	color: var(--color-text-maxcontrast);
	font-size: 0.85em;
	font-weight: 600;
	white-space: nowrap;
}

.table tbody th {
	font-weight: normal;
}

.table tbody th > * + * {
	margin-inline-start: calc(var(--default-grid-baseline) * 2);
}

.table tbody tr:last-child th,
.table tbody tr:last-child td {
	border-bottom: none;
}

.table tbody tr:hover {
	background-color: var(--color-background-hover);
}

.row_off {
	color: var(--color-text-maxcontrast);
}

.link {
	color: var(--color-main-text);
	font-weight: 600;
	text-decoration: underline;
	text-decoration-color: var(--color-border-dark, var(--color-border));
	text-underline-offset: 3px;
}

.link:hover,
.link:focus-visible {
	text-decoration-color: currentColor;
}

.checkLink {
	color: var(--color-main-text);
	font-weight: 600;
	text-decoration: none;
}

.checkLink:hover,
.checkLink:focus-visible {
	text-decoration: underline;
	text-underline-offset: 3px;
}

.yes,
.no {
	display: inline-flex;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 1);
}

.yes {
	color: var(--color-success-text);
	font-weight: 600;
}

.no {
	color: var(--color-text-maxcontrast);
}

@media (max-width: 600px) {
	.table thead {
		display: none;
	}

	.table,
	.table tbody,
	.table tr,
	.table th,
	.table td {
		display: block;
		width: 100%;
	}

	.table tr {
		padding-block: calc(var(--default-grid-baseline) * 2);
		border-bottom: 1px solid var(--color-border);
	}

	.table th,
	.table td {
		padding: calc(var(--default-grid-baseline) * 1) 0;
		border: none;
	}

	.table td[data-label]::before {
		content: attr(data-label) ': ';
		color: var(--color-text-maxcontrast);
		font-size: 0.9em;
	}
}
</style>
