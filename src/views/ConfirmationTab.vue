<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { ConfirmationOverview, ConfirmationPolicy } from '../types.ts'

import { mdiAccountAlertOutline, mdiAccountClockOutline, mdiLaptop, mdiListStatus, mdiRefresh, mdiShieldAccountOutline, mdiTimerOutline } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onActivated, onBeforeUnmount, onDeactivated, onMounted, ref } from 'vue'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import SectionCard from '../components/common/SectionCard.vue'
import SettingsGroup from '../components/common/SettingsGroup.vue'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import MethodSteps from '../components/confirmation/MethodSteps.vue'
import PendingApprovals from '../components/confirmation/PendingApprovals.vue'
import PolicyTable from '../components/confirmation/PolicyTable.vue'
import UnconfirmableAccounts from '../components/confirmation/UnconfirmableAccounts.vue'
import { errorMessage, fetchConfirmation } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { state } from '../store.ts'
import { APP_ID } from '../utils/format.ts'

/** Waiting logins are looked up again this often while the tab is open */
const APPROVALS_REFRESH = 30_000

const KNOWN_DEVICE_SETTINGS = ['known_device_enabled', 'known_device_duration']
const APPROVAL_SETTINGS = ['step_up_admin_approval', 'step_up_admin_approval_ttl']
/** Edited in the reasons table */
const POLICY_SETTINGS = ['step_up_known_device_ok_for']

const data = ref<ConfirmationOverview | null>(null)
const loadError = ref<string | null>(null)
const refreshing = ref(false)
let timer: ReturnType<typeof setInterval> | undefined

const byName = (names: string[]) => state.settings.filter((s) => names.includes(s.name))
const knownDeviceSettings = computed(() => byName(KNOWN_DEVICE_SETTINGS))
const approvalSettings = computed(() => byName(APPROVAL_SETTINGS))
const otherSettings = computed(() => state.settings.filter((s) => s.group === 'step_up'
	&& !s.name.startsWith('step_up_no_method_')
	&& ![...KNOWN_DEVICE_SETTINGS, ...APPROVAL_SETTINGS, ...POLICY_SETTINGS].includes(s.name)))
const approvalOn = computed(() => state.settings.find((s) => s.name === 'step_up_admin_approval')?.value === true)

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
 * @param policies - The reasons after a change
 */
function onPolicies(policies: ConfirmationPolicy[]) {
	if (data.value) {
		data.value.policies = policies
	}
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

onMounted(() => {
	void load()
	startTimer()
})
onActivated(() => {
	void load()
	startTimer()
})
onDeactivated(stopTimer)
onBeforeUnmount(stopTimer)
</script>

<template>
	<div :class="$style.confirmation">
		<NcNoteCard v-if="loadError" type="error" :text="loadError" />
		<div v-else-if="data === null" :class="$style.skeleton" aria-busy="true">
			<SkeletonBlock height="220px" />
			<SkeletonBlock height="320px" />
			<SkeletonBlock height="160px" />
		</div>

		<template v-else>
			<SectionCard :heading="t(APP_ID, 'How Nextcloud confirms it is really the user')" :icon="mdiShieldAccountOutline">
				<template #description>
					{{ t(APP_ID, 'Some logins need extra confirmation, for example when the address took part in an attack. Nextcloud tries these ways in this order and uses the first one the account has. Users with a second factor notice nothing extra.') }}
				</template>
				<MethodSteps :methods="data.methods" />
			</SectionCard>

			<SectionCard :heading="t(APP_ID, 'What each reason accepts')" :icon="mdiListStatus">
				<template #description>
					{{ t(APP_ID, 'For each reason: whether a remembered device is enough, and what happens when the account has no way to confirm the login. Changes are saved at once.') }}
				</template>
				<PolicyTable :policies="data.policies" :outcomes="data.outcomes" @changed="onPolicies" />
			</SectionCard>

			<SectionCard id="approvals" :heading="t(APP_ID, 'Logins waiting for an administrator')" :icon="mdiAccountClockOutline">
				<template #description>
					{{ approvalOn
						? n(APP_ID, 'When nothing else can confirm a login, it waits for an administrator. %n administrator can approve.', 'When nothing else can confirm a login, it waits for an administrator. %n administrators can approve.', data.approvers)
						: t(APP_ID, 'Off: logins that nothing else can confirm follow the table above. Turn it on to let an administrator approve them instead.') }}
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
				<SettingsGroup :settings="approvalSettings" />
				<PendingApprovals :approvals="data.approvals" @decided="load()" />
			</SectionCard>

			<SectionCard id="accounts" :heading="t(APP_ID, 'Accounts that cannot confirm a login')" :icon="mdiAccountAlertOutline">
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

			<div :class="$style.columns">
				<SectionCard :heading="t(APP_ID, 'Remembered devices')" :icon="mdiLaptop">
					<template #description>
						{{ t(APP_ID, 'Only a fingerprint of a random cookie is stored. Users see and remove their devices in their security settings. A device is forgotten when they answer "No, it was not me", when their password changes, and when their session seems stolen.') }}
					</template>
					<SettingsGroup :settings="knownDeviceSettings" />
				</SectionCard>

				<SectionCard :heading="t(APP_ID, 'Codes and time limits')" :icon="mdiTimerOutline">
					<template #description>
						{{ t(APP_ID, 'How long codes are valid, and how long a login may wait for its confirmation.') }}
					</template>
					<SettingsGroup :settings="otherSettings" />
				</SectionCard>
			</div>
		</template>
	</div>
</template>

<style module>
.confirmation {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 5);
}

.skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.columns {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(min(100%, 380px), 1fr));
	gap: calc(var(--default-grid-baseline) * 5);
	align-items: start;
}
</style>
