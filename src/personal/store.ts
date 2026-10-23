/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ResourceOptions } from '../composables/useResource.ts'
import type { KnownDevice, LoggedOutElsewhere, ManageSummary, PersonalActivity, PersonalOverview, PersonalState, SecurityEvent, StaleCredential, TrustedNetwork } from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { reactive, ref } from 'vue'
import { invalidate, resource, update, useResource } from '../composables/useResource.ts'
import { errorMessage } from '../services/api.ts'
import { fetchSecureAccountProgress } from '../services/secureAccount.ts'
import { APP_ID } from '../utils/format.ts'
import { t } from '../utils/l10n.ts'
import {
	confirmEvent,
	denyEvent,
	fetchActivity,
	fetchKnownDevices,
	fetchOverview,
	fetchStaleCredentials,
	fetchTrustedNetworks,
	logOutElsewhere,
	removeAllStaleCredentials,
	removeKnownDevice,
	removeStaleCredential,
	removeTrustedNetwork,
} from './api.ts'

/** Timeline entries loaded first, and added by each "Show more" */
export const ACTIVITY_PAGE = 20
/** The server's bound */
export const ACTIVITY_MAX = 100

/** How many timeline entries are loaded */
const activityLimit = ref(ACTIVITY_PAGE)

/**
 * @param signal - Cancels the request
 */
function loadActivity(signal: AbortSignal): Promise<PersonalActivity> {
	return fetchActivity(activityLimit.value, 30, signal)
}

const overview = resource<PersonalOverview>('personal-overview', fetchOverview, { keep: true })
const activity = resource<PersonalActivity>('personal-activity', loadActivity, { keep: true })
const staleCredentials = resource<StaleCredential[]>('personal-stale-credentials', fetchStaleCredentials, { keep: true })

/**
 * The data layer of the personal page: the overview at the top, the open
 * questions and the timeline, the counts of the "Manage" section and the
 * app passwords and devices not used for 90 days.
 * Sections read it here and change things only through the actions here,
 * which load again what a change makes out of date.
 */
export const personal = reactive({
	get overview(): PersonalOverview | null {
		return overview.data
	},
	set overview(value: PersonalOverview | null) {
		overview.data = value
	},
	manage: { devices: 0, networks: 0, otherBrowsers: 0 } as ManageSummary,
	/** App passwords and remembered browsers not used for 90 days */
	get staleCredentials(): StaleCredential[] {
		return staleCredentials.data ?? []
	},
	set staleCredentials(value: StaleCredential[]) {
		staleCredentials.data = value
	},
	/** The open questions and the timeline; null until loaded */
	get activity(): PersonalActivity | null {
		return activity.data
	},
	set activity(value: PersonalActivity | null) {
		activity.data = value
	},
	get activityError(): string | null {
		return activity.error === null ? null : errorMessage(activity.error, t(APP_ID, 'Your recent activity could not be loaded. Please try again.'))
	},
	get activityLoading(): boolean {
		return activity.loading
	},
	get activityLimit(): number {
		return activityLimit.value
	},
	set activityLimit(value: number) {
		activityLimit.value = value
	},
})

/**
 * Take the state the page came with.
 */
export function initPersonalState(): void {
	const state = loadState<PersonalState | null>(APP_ID, 'personal', null)
	if (state !== null) {
		personal.overview = state.overview
		personal.manage = state.manage
		personal.staleCredentials = state.staleCredentials ?? []
	}
}

/**
 * Load the open questions and the timeline while the page is shown; the
 * previous ones stay visible while they reload.
 */
export function useActivity(): void {
	useResource('personal-activity', loadActivity)
}

/**
 * Load the activity again, e.g. after it could not be loaded.
 */
export function reloadActivity(): Promise<void> {
	return invalidate('personal-activity')
}

/**
 * Load more timeline entries, up to the server's bound.
 */
export function showMoreActivity(): Promise<void> {
	personal.activityLimit = Math.min(personal.activityLimit + ACTIVITY_PAGE, ACTIVITY_MAX)
	return invalidate('personal-activity')
}

/**
 * Answer "Was this you?". An answered question leaves the list at once;
 * the timeline and the overview then show the answer. "Yes" trusts the
 * network of the event for a while.
 *
 * @param id - The event
 * @param answer - "Yes, it was me" or "No, it was not me"
 * @return the event as the server has it now; without a verdict when the answer only told the administrators
 */
export async function answerEvent(id: string, answer: 'confirm' | 'deny'): Promise<SecurityEvent> {
	const event = await (answer === 'confirm' ? confirmEvent(id) : denyEvent(id))
	if (event.verdict === null) {
		return event
	}
	update<PersonalActivity>('personal-activity', (current) => {
		current.questions = current.questions.filter((question) => question.id !== id)
	})
	if (answer === 'confirm') {
		personal.manage.networks = Math.max(personal.manage.networks, 1)
	}
	await invalidate('personal-activity', 'personal-overview', 'personal-networks')
	return event
}

/**
 * The remembered devices.
 *
 * @param options - Resource options
 */
export function useKnownDevices(options: ResourceOptions = {}) {
	return useResource('personal-devices', fetchKnownDevices, options)
}

/**
 * Forget a remembered device.
 *
 * @param id - The device
 */
export async function forgetDevice(id: string): Promise<void> {
	await removeKnownDevice(id)
	update<KnownDevice[]>('personal-devices', (devices) => {
		const left = devices.filter((device) => device.id !== id)
		personal.manage.devices = left.length
		return left
	})
}

/**
 * The trusted networks.
 *
 * @param options - Resource options
 */
export function useTrustedNetworks(options: ResourceOptions = {}) {
	return useResource('personal-networks', fetchTrustedNetworks, options)
}

/**
 * Stop trusting a network.
 *
 * @param id - The entry
 */
export async function forgetNetwork(id: string): Promise<void> {
	await removeTrustedNetwork(id)
	update<TrustedNetwork[]>('personal-networks', (networks) => {
		const left = networks.filter((network) => network.id !== id)
		personal.manage.networks = left.length
		return left
	})
}

/**
 * End the other sessions. Their remembered devices are forgotten too.
 */
export async function logOutOtherBrowsers(): Promise<LoggedOutElsewhere> {
	const result = await logOutElsewhere()
	personal.manage.otherBrowsers = 0
	await invalidate('personal-devices', 'personal-stale-credentials')
	return result
}

/**
 * Remove an app password or device not used for 90 days.
 *
 * @param id - The credential
 */
export async function removeUnusedCredential(id: number): Promise<void> {
	await removeStaleCredential(id)
	update<StaleCredential[]>('personal-stale-credentials', (credentials) => credentials.filter((credential) => credential.id !== id))
}

/**
 * Remove every app password and device not used for 90 days.
 *
 * @return how many were removed
 */
export async function removeUnusedCredentials(): Promise<number> {
	const { removed } = await removeAllStaleCredentials()
	personal.staleCredentials = []
	return removed
}

/**
 * The progress of "Secure my account", for the card on top.
 *
 * @param options - Resource options
 */
export function useSecureAccountProgress(options: ResourceOptions = {}) {
	return useResource('secure-account-progress', fetchSecureAccountProgress, options)
}
