<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationPreset } from '../../types.ts'

import { mdiAccountAlertOutline, mdiAccountClockOutline, mdiLaptop, mdiListStatus, mdiRefresh, mdiShieldAccountOutline, mdiTimerOutline } from '@mdi/js'
import { computed, nextTick, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcCheckboxRadioSwitch from '@nextcloud/vue/components/NcCheckboxRadioSwitch'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SectionCard from '../common/SectionCard.vue'
import SettingsGroup from '../common/SettingsGroup.vue'
import ShowMore from '../common/ShowMore.vue'
import SkeletonBlock from '../common/SkeletonBlock.vue'
import MethodSteps from '../confirmation/MethodSteps.vue'
import PendingApprovals from '../confirmation/PendingApprovals.vue'
import PolicyTable from '../confirmation/PolicyTable.vue'
import UnconfirmableAccounts from '../confirmation/UnconfirmableAccounts.vue'
import { useAction } from '../../composables/useAction.ts'
import { saveSettings, state, useWaitingLogins, waitingLogins } from '../../store.ts'
import { chooseConfirmationPreset, useConfirmation } from '../../stores/settings.ts'
import { APP_ID, formatNumber } from '../../utils/format.ts'
import { n, t } from '../../utils/l10n.ts'

const KNOWN_DEVICE = 'known_device_enabled'
const ADMIN_APPROVAL = 'step_up_admin_approval'
const ADMIN_NETWORKS = 'admin_trusted_networks_only'
const TRUSTED_NETWORKS = 'risky_network_office_networks'

const PRESETS: { value: ConfirmationPreset, label: () => string, description: () => string }[] = [
	{ value: 'recommended', label: () => t(APP_ID, 'Recommended'), description: () => t(APP_ID, 'Refuse it when an attack is likely; otherwise let it in and tell the user and you.') },
	{ value: 'refuse', label: () => t(APP_ID, 'Refuse it'), description: () => t(APP_ID, 'Safest, but it can lock out someone who only lacks an email address.') },
	{ value: 'allow', label: () => t(APP_ID, 'Let it in and notify'), description: () => t(APP_ID, 'The user and you are told. With a leaked password, a new one is required.') },
]

const { data, error, loading: counting, reload: recount } = useConfirmation({ failure: () => t(APP_ID, 'The overview could not be loaded. Please reload the page.') })
/** A failed reload keeps the overview shown */
const loadError = computed(() => data.value === null ? error.value : null)
const { loading: lookingForLogins, reload: lookForLogins } = useWaitingLogins()
const { busy, run } = useAction()
/** Whether the reasons table is shown */
const reasonsOpen = ref(false)

const switchOn = (name: string) => state.settings.find((s) => s.name === name)?.value === true
const approvalOn = computed(() => switchOn(ADMIN_APPROVAL))
const adminNetworksOn = computed(() => switchOn(ADMIN_NETWORKS))
const trustedNetworks = computed(() => state.settings.filter((s) => s.name === TRUSTED_NETWORKS))
const noTrustedNetworks = computed(() => {
	const value = trustedNetworks.value[0]?.value
	return !Array.isArray(value) || value.length === 0
})

/**
 * Set what happens to every login that nothing can confirm.
 *
 * @param preset - The choice
 */
function choose(preset: ConfirmationPreset) {
	if (data.value === null || preset === data.value.preset) {
		return
	}
	run('preset', () => chooseConfirmationPreset(preset), {
		done: t(APP_ID, 'Saved'),
		fallback: t(APP_ID, 'The change could not be saved. Please try again.'),
	})
}

/**
 * Save one of the switches at once.
 *
 * @param name - The setting
 * @param on - Its new value
 */
function toggle(name: string, on: boolean) {
	run(name, () => saveSettings({ [name]: on }), {
		done: t(APP_ID, 'Saved'),
		fallback: t(APP_ID, 'The change could not be saved. Please try again.'),
	})
}

/**
 * Show the reasons table, where each reason is set on its own.
 */
async function showReasons() {
	reasonsOpen.value = true
	await nextTick()
	document.getElementById('settings-confirmation-reasons')?.scrollIntoView({ block: 'start', behavior: 'smooth' })
}
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
					<div data-test="admin-networks">
						<NcCheckboxRadioSwitch
							type="switch"
							:modelValue="adminNetworksOn"
							:loading="busy === ADMIN_NETWORKS"
							:disabled="busy !== null"
							:description="t(APP_ID, 'Password logins of administrators from anywhere else need a second factor, an email code or another administrator\'s approval; a remembered device is not enough. Apps with app passwords are not affected.')"
							@update:modelValue="toggle(ADMIN_NETWORKS, $event)">
							{{ t(APP_ID, 'Administrators log in from trusted networks only') }}
						</NcCheckboxRadioSwitch>
					</div>
					<div v-if="adminNetworksOn" :class="$style.networks" data-test="admin-networks-details">
						<NcNoteCard
							v-if="noTrustedNetworks"
							type="warning"
							data-test="admin-networks-empty"
							:text="t(APP_ID, 'There are no trusted networks yet, so every administrator login from anywhere needs confirmation.')" />
						<SettingsGroup v-if="trustedNetworks.length > 0" :settings="trustedNetworks" />
						<p :class="$style.muted">
							{{ t(APP_ID, 'Locked out? Run "occ config:app:set intrusion_detection admin_trusted_networks_only --value=false" on the server.') }}
						</p>
					</div>
				</div>
			</SectionCard>

			<SectionCard
				v-if="approvalOn || waitingLogins.length > 0"
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
					<NcButton :disabled="lookingForLogins" :aria-label="t(APP_ID, 'Look for waiting logins')" @click="lookForLogins()">
						<template #icon>
							<NcLoadingIcon v-if="lookingForLogins" :size="20" />
							<NcIconSvgWrapper v-else :path="mdiRefresh" />
						</template>
						{{ t(APP_ID, 'Refresh') }}
					</NcButton>
				</template>
				<PendingApprovals :approvals="waitingLogins" />
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
					<PolicyTable :policies="data.policies" :outcomes="data.outcomes" />
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
					<NcButton :disabled="counting" @click="recount()">
						<template #icon>
							<NcLoadingIcon v-if="counting" :size="20" />
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
	gap: var(--ids-space-5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-3);
}

.choice {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-1);
	margin: 0;
	padding: 0;
	border: none;
}

.custom {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: var(--ids-space-2);
	margin: 0;
	padding: var(--ids-space-2) var(--ids-space-3);
	border-radius: var(--border-radius-element);
	background-color: var(--color-background-hover);
	font-weight: 600;
}

.muted {
	composes: muted from '../../styles/shared.module.css';
	margin: 0;
}

.switches {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding-top: var(--ids-space-4);
	border-top: 1px solid var(--color-border);
}

.columns {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 380px), 1fr));
	gap: var(--ids-space-5);
	align-items: start;
}

.limits {
	margin: 0;
	line-height: 1.5;
}

.networks {
	display: flex;
	flex-direction: column;
	gap: var(--ids-space-2);
	padding-inline-start: var(--ids-space-4);
}
</style>
