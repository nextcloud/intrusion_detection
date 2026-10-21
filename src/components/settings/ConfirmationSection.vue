<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationOverview, ConfirmationPolicy, ConfirmationPreset } from '../../types.ts'

import { mdiAccountAlertOutline, mdiAccountClockOutline, mdiLaptop, mdiListStatus, mdiRefresh, mdiShieldAccountOutline, mdiTimerOutline } from '@mdi/js'
import { showError } from '@nextcloud/dialogs'
import { n, t } from '@nextcloud/l10n'
import { computed, nextTick, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SectionCard from '../common/SectionCard.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import MethodSteps from '../confirmation/MethodSteps.vue'
import PendingApprovals from '../confirmation/PendingApprovals.vue'
import PolicyTable from '../confirmation/PolicyTable.vue'
import UnconfirmableAccounts from '../confirmation/UnconfirmableAccounts.vue'
import { useAnnouncer } from '../../composables/useAnnouncer.ts'
import { errorMessage, fetchConfirmation, isCancelled, setConfirmationPreset, updateSettings } from '../../services/api.ts'
import { logger } from '../../services/logger.ts'
import { refreshSettings, state } from '../../store.ts'
import { APP_ID, formatNumber } from '../../utils/format.ts'

/** Waiting logins are looked up again this often while the tab is open */
const APPROVALS_REFRESH = 30_000

const KNOWN_DEVICE = 'known_device_enabled'
const ADMIN_APPROVAL = 'step_up_admin_approval'

const PRESETS: { value: ConfirmationPreset, label: () => string, description: () => string }[] = [
	{ value: 'recommended', label: () => t(APP_ID, 'Recommended'), description: () => t(APP_ID, 'Refuse it when an attack is likely; otherwise let it in and tell the user and you.') },
	{ value: 'refuse', label: () => t(APP_ID, 'Refuse it'), description: () => t(APP_ID, 'Safest, but it can lock out someone who only lacks an email address.') },
	{ value: 'allow', label: () => t(APP_ID, 'Let it in and notify'), description: () => t(APP_ID, 'The user and you are told. With a leaked password, a new one is required.') },
]

const data = ref<ConfirmationOverview | null>(null)
const loadError = ref<string | null>(null)
const refreshing = ref(false)
const busy = ref<string | null>(null)
/** Whether the reasons table is shown */
const reasonsOpen = ref(false)
const { announce } = useAnnouncer()
let timer: ReturnType<typeof setInterval> | undefined

const switchOn = (name: string) => state.settings.find((s) => s.name === name)?.value === true
const approvalOn = computed(() => switchOn(ADMIN_APPROVAL))

/**
 * Load the overview.
 */
async function load() {
	await fetchOverview(false)
}

/**
 * Load the overview with the accounts counted again.
 */
async function recount() {
	await fetchOverview(true)
}

/**
 * @param refresh - Whether to count the accounts again
 */
async function fetchOverview(refresh: boolean) {
	refreshing.value = true
	try {
		data.value = await fetchConfirmation(refresh)
		loadError.value = null
	} catch (error) {
		logger.error('Could not load the confirmation overview', { error })
		if (data.value === null) {
			loadError.value = errorMessage(error, t(APP_ID, 'The overview could not be loaded. Please reload the page.'))
		}
	} finally {
		refreshing.value = false
	}
}

/**
 * Set what happens to every login that nothing can confirm.
 *
 * @param preset - The choice
 */
async function choose(preset: ConfirmationPreset) {
	if (data.value === null || preset === data.value.preset) {
		return
	}
	busy.value = 'preset'
	try {
		const result = await setConfirmationPreset(preset)
		data.value.preset = result.preset
		data.value.policies = result.policies
		announce(t(APP_ID, 'Saved'))
		refreshSettings().catch((error) => logger.error('Could not reload the settings', { error }))
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the confirmation choice', { error })
			showError(errorMessage(error, t(APP_ID, 'The change could not be saved. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}

/**
 * Save one of the switches at once.
 *
 * @param name - The setting
 * @param on - Its new value
 */
async function toggle(name: string, on: boolean) {
	busy.value = name
	try {
		const payload = await updateSettings({ [name]: on })
		state.settings = payload.settings
		state.templates = payload.templates
		announce(t(APP_ID, 'Saved'))
		if (name === ADMIN_APPROVAL) {
			await load()
		}
	} catch (error) {
		if (!isCancelled(error)) {
			logger.error('Could not save the confirmation setting', { error })
			showError(errorMessage(error, t(APP_ID, 'The change could not be saved. Please try again.')))
		}
	} finally {
		busy.value = null
	}
}

/**
 * Show the reasons table, where each reason is set on its own.
 */
async function showReasons() {
	reasonsOpen.value = true
	await nextTick()
	document.getElementById('settings-confirmation-reasons')?.scrollIntoView({ block: 'start', behavior: 'smooth' })
}

/**
 * @param policies - The reasons after a change
 */
async function onPolicies(policies: ConfirmationPolicy[]) {
	if (data.value) {
		data.value.policies = policies
	}
	// The table changes single reasons, which can turn a preset into "custom".
	await load()
}

/**
 * Look the waiting logins up again while the tab is visible.
 */
function startTimer() {
	stopTimer()
	timer = setInterval(() => {
		if (document.visibilityState === 'visible' && !refreshing.value) {
			void load()
		}
	}, APPROVALS_REFRESH)
}

/**
 * Stop looking.
 */
function stopTimer() {
	if (timer !== undefined) {
		clearInterval(timer)
		timer = undefined
	}
}

// Opening the tab counts the accounts again; the timer only looks for waiting logins.
let justMounted = true
onMounted(() => {
	void recount()
	startTimer()
})
onActivated(() => {
	// Inside KeepAlive, the first activation comes with the mount.
	if (justMounted) {
		justMounted = false
		return
	}
	void recount()
	startTimer()
})
onDeactivated(stopTimer)
onBeforeUnmount(stopTimer)
</script>

<template>
	<div :class="$style.stack">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock height="220px" />
		</div>

		<template v-else>
			<SectionCard level="h4" :heading="t(APP_ID, 'When a risky login cannot be confirmed')" :icon="mdiShieldAccountOutline">
				<template #description>
					{{ t(APP_ID, 'Some logins need extra confirmation, for example from an address that took part in an attack. Users with a second factor or an email address confirm it; for everyone else, you decide.') }}
				</template>

				<fieldset :class="$style.choice" data-test="preset">
					<legend class="hidden-visually">
						{{ t(APP_ID, 'When a risky login cannot be confirmed') }}
					</legend>
					<NcCheckboxRadioSwitch
						v-for="option in PRESETS"
						:key="option.value"
						type="radio"
						name="ids-confirmation-preset"
						:value="option.value"
						:modelValue="data.preset"
						:description="option.description()"
						:disabled="busy !== null"
						@update:modelValue="choose(option.value)">
						{{ option.label() }}
					</NcCheckboxRadioSwitch>
				</fieldset>
				<p v-if="data.preset === 'custom'" :class="$style.custom" data-test="preset-custom">
					<span>{{ t(APP_ID, 'Custom: set for each reason on its own.') }}</span>
					<NcButton v-if="!reasonsOpen" variant="tertiary" @click="showReasons">
						{{ t(APP_ID, 'Show each reason') }}
					</NcButton>
				</p>
				<p :class="$style.muted" data-test="users-count">
					{{ n(APP_ID, '{count} of {active} active accounts has no way to confirm a login.', '{count} of {active} active accounts have no way to confirm a login.', data.users.withoutMethod, { count: formatNumber(data.users.withoutMethod), active: formatNumber(data.users.active) }) }}
				</p>

				<div :class="$style.switches">
					<NcCheckboxRadioSwitch
						type="switch"
						:modelValue="switchOn(KNOWN_DEVICE)"
						:loading="busy === KNOWN_DEVICE"
						:disabled="busy !== null"
						:description="t(APP_ID, 'After confirming, users may let this browser confirm later logins.')"
						@update:modelValue="toggle(KNOWN_DEVICE, $event)">
						{{ t(APP_ID, 'Remember devices') }}
					</NcCheckboxRadioSwitch>
					<NcCheckboxRadioSwitch
						type="switch"
						:modelValue="approvalOn"
						:loading="busy === ADMIN_APPROVAL"
						:disabled="busy !== null"
						:description="t(APP_ID, 'A login nothing else can confirm waits until an administrator approves it.')"
						@update:modelValue="toggle(ADMIN_APPROVAL, $event)">
						{{ t(APP_ID, 'Administrators can approve logins') }}
					</NcCheckboxRadioSwitch>
				</div>
			</SectionCard>

			<SectionCard
				v-if="approvalOn || data.approvals.length > 0"
				id="settings-approvals"
				level="h4"
				:heading="t(APP_ID, 'Logins waiting for an administrator')"
				:icon="mdiAccountClockOutline">
				<template #description>
					{{ approvalOn
						? n(APP_ID, '%n administrator can approve.', '%n administrators can approve.', data.approvers)
						: t(APP_ID, 'Approval is off; these logins can still be decided until they expire.') }}
				</template>
				<template #actions>
					<NcButton :disabled="refreshing" :aria-label="t(APP_ID, 'Look for waiting logins')" @click="load()">
						<template #icon>
							<NcLoadingIcon v-if="refreshing" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiRefresh" />
						</template>
						{{ t(APP_ID, 'Refresh') }}
					</NcButton>
				</template>
				<PendingApprovals :approvals="data.approvals" @decided="load()" />
			</SectionCard>

			<SectionCard
				id="settings-confirmation-reasons"
				level="h4"
				:heading="t(APP_ID, 'What each reason accepts')"
				:icon="mdiListStatus">
				<template #description>
					{{ t(APP_ID, 'For each reason: whether a remembered device is enough, and what happens when the account has no way to confirm the login. Changes are saved at once.') }}
				</template>
				<ShowMore v-model:open="reasonsOpen" :label="t(APP_ID, 'Customise each reason')" data-test="reasons-toggle">
					<PolicyTable :policies="data.policies" :outcomes="data.outcomes" @changed="onPolicies" />
				</ShowMore>
			</SectionCard>

			<SectionCard
				id="settings-confirmation-accounts"
				level="h4"
				:heading="t(APP_ID, 'Accounts that cannot confirm a login')"
				:icon="mdiAccountAlertOutline">
				<template #description>
					{{ t(APP_ID, 'Active accounts are enabled accounts that logged in at least once. The counts are at most an hour old.') }}
				</template>
				<template #actions>
					<NcButton :disabled="refreshing" @click="recount">
						<template #icon>
							<NcLoadingIcon v-if="refreshing" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiRefresh" />
						</template>
						{{ t(APP_ID, 'Count again') }}
					</NcButton>
				</template>
				<UnconfirmableAccounts :users="data.users" :admins="data.admins" />
			</SectionCard>

			<ShowMore :label="t(APP_ID, 'How logins are confirmed, remembered devices and time limits')" data-test="confirmation-more">
				<div :class="$style.stack">
					<SectionCard level="h4" :heading="t(APP_ID, 'How Nextcloud confirms it is really the user')" :icon="mdiShieldAccountOutline">
						<template #description>
							{{ t(APP_ID, 'Nextcloud tries these ways in this order and uses the first one the account has.') }}
						</template>
						<MethodSteps :methods="data.methods" />
					</SectionCard>

					<div :class="$style.columns">
						<SectionCard level="h4" :heading="t(APP_ID, 'Remembered devices')" :icon="mdiLaptop">
							<template #description>
								{{ t(APP_ID, 'Only a fingerprint of a random cookie is stored. Users see and remove their devices in their security settings. A device is forgotten when they answer "No, it was not me", when their password changes, and when their session seems stolen.') }}
							</template>
							<p :class="$style.limits" data-test="known-device-time">
								{{ state.templates.knownDeviceTime }}
							</p>
						</SectionCard>

						<SectionCard level="h4" :heading="t(APP_ID, 'Codes and time limits')" :icon="mdiTimerOutline">
							<template #description>
								{{ t(APP_ID, 'How long codes are valid, and how long a login may wait for its confirmation.') }}
							</template>
							<p :class="$style.limits" data-test="confirmation-times">
								{{ state.templates.confirmationTimes }}
							</p>
						</SectionCard>
					</div>
				</div>
			</ShowMore>
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

.choice {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1);
	margin: 0;
	padding: 0;
	border: none;
}

.custom {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2);
	margin: 0;
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-weight: 600;
}

.muted {
	margin: 0;
	color: var(--color-text-maxcontrast);
}

.switches {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	padding-top: calc(var(--default-grid-baseline) * 4);
	border-top: 1px solid var(--color-border);
}

.columns {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 380px), 1fr));
	gap: calc(var(--default-grid-baseline) * 5);
	align-items: start;
}

.limits {
	margin: 0;
	line-height: 1.5;
}
</style>
