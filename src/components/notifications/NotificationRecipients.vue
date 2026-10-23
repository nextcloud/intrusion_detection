<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { Notifications, TestAlertResult } from '../../types.ts'

import { mdiAccountGroupOutline, mdiAlertCircleOutline, mdiBellOutline, mdiCheckCircleOutline, mdiEmailOffOutline, mdiEmailOutline } from '@mdi/js'
import { showSuccess, showWarning } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, ref, watch } from 'vue'
import NcAvatar from '@nextcloud/vue/components/NcAvatar'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcSettingsSelectGroup from '@nextcloud/vue/components/NcSettingsSelectGroup'
import LiveSentence from '../checks/LiveSentence.vue'
import SectionCard from '../common/SectionCard.vue'
import SelectField from '../common/SelectField.vue'
import { useAction } from '../../composables/useAction.ts'
import { sendTestAlert } from '../../services/api.ts'
import { saveSettings, severityLabel, state } from '../../store.ts'
import { APP_ID, fillTemplate } from '../../utils/format.ts'

/** "Who is notified": the groups, the email threshold, who that is now, and a test alert */
defineProps<{
	data: Notifications
}>()

const groups = ref<string[]>([])
const severity = ref('high')
const { busy, run } = useAction()
const saving = computed(() => busy.value === 'save')
const testing = computed(() => busy.value === 'test')
const testResult = ref<TestAlertResult | null>(null)

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
	if (severity.value === 'never') {
		return [{ text: t(APP_ID, 'No emails are sent. Alerts appear only as notifications in Nextcloud.') }]
	}
	const template = severity.value === 'low'
		? t(APP_ID, 'Every detection with a notification is also emailed, at most once per check and hour.')
		: t(APP_ID, 'Detections of severity {severity} or higher are also emailed, at most once per check and hour. The others appear only as notifications in Nextcloud.')
	return fillTemplate(template, { severity: severityLabel(severity.value) })
})

/**
 * Save the groups and the email severity.
 */
function save() {
	run('save', () => saveSettings({ notify_admin_group: groups.value, notify_admin_email_min_severity: severity.value }), {
		done: t(APP_ID, 'Saved'),
		fallback: t(APP_ID, 'The settings could not be saved. Please try again.'),
	})
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
 * Send the test alert. When the email part failed, that is a warning of its own.
 */
function test() {
	run('test', async () => {
		testResult.value = await sendTestAlert()
		const sent = t(APP_ID, 'Test alert sent. Look at the bell at the top right.')
		const email = emailResult.value
		if (email === null || email.ok) {
			showSuccess(email === null ? sent : `${sent} ${email.text}`)
		} else {
			showSuccess(sent)
			showWarning(email.text)
		}
	}, { fallback: t(APP_ID, 'The test alert could not be sent. Please try again in a few minutes.') })
}
</script>

<template>
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
</template>

<style module>
.test {
	display: flex;
	flex-direction: column;
	align-items: flex-start;
	gap: var(--ids-space-2);
	padding-top: var(--ids-space-4);
	border-top: 1px solid var(--color-border);
}

.form {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-4);
}

.form__save {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
}

.field {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
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
	composes: muted from '../../styles/shared.module.css';
}

.people {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding-top: var(--ids-space-4);
	border-top: 1px solid var(--color-border);
}

.people__count {
	margin: 0;
	font-weight: 600;
}

.people__list {
	composes: plainList from '../../styles/shared.module.css';
	display: flex;
	flex-wrap: wrap;
	gap: var(--ids-space-2);
}

.person {
	display: inline-flex;
	align-items: center;
	gap: var(--ids-space-2);
	padding-block: 2px;
	padding-inline: 2px var(--ids-space-3);
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
	composes: muted from '../../styles/shared.module.css';
	font-size: 0.85em;
}

.results {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	margin: 0;
	padding: var(--ids-space-3);
	border-radius: var(--border-radius-large);
	background-color: var(--color-background-hover);
	list-style: none;
}

.result {
	display: flex;
	align-items: flex-start;
	gap: var(--ids-space-2);
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
</style>
