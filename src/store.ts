/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ResourceOptions } from './composables/useResource.ts'
import type {
	AdminGrantRequest,
	Ban,
	Category,
	Check,
	CheckList,
	Choice,
	DetectionFilters,
	GlobalSetting,
	IncidentRequest,
	InitialState,
	LoginApproval,
	Mode,
	ParamType,
	ParamValue,
	ProtectionLevel,
	SettingsPayload,
	Status,
} from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { computed, reactive, ref } from 'vue'
import { invalidate, resource, useResource } from './composables/useResource.ts'
import {
	addBan,
	ApiError,
	approveRequest,
	fetchAdminGrants,
	fetchChecks,
	fetchProtectionLevel,
	fetchSettings,
	fetchStatus,
	fetchWaitingLogins,
	liftBan,
	rejectRequest,
	resetCheck,
	resetSettings,
	updateCheck,
	updateLearning,
	updateProtectionLevel,
	updateSettings,
} from './services/api.ts'
import { APP_ID } from './utils/format.ts'

/**
 * The data layer of the admin page: what the tabs share, and the changes
 * that touch it. Components read data here and in `stores/`, and change
 * things only through their actions; each action invalidates the data the
 * change makes out of date.
 */
const initial = loadState<InitialState | null>(APP_ID, 'admin', null)

const status = resource<Status>('status', fetchStatus, { initial: initial?.status ?? null, keep: true })
const checkList = resource<CheckList>('checks', fetchChecks, { initial: initial?.checks ?? null, keep: true })
const settingsPayload = resource<SettingsPayload>('settings', fetchSettings, { initial: initial?.settings ?? null, keep: true })
const level = resource<{ level: ProtectionLevel }>('protection-level', fetchProtectionLevel, { initial: { level: initial?.protectionLevel ?? 'recommended' }, keep: true })
const waiting = resource<LoginApproval[]>('waiting-logins', fetchWaitingLogins, { keep: true })
const grants = resource<AdminGrantRequest[]>('admin-grants', fetchAdminGrants, { keep: true })

/** What the server derives from the global settings */
const FROM_SETTINGS = ['status', 'checks', 'protection-level', 'bans', 'blocklists', 'confirmation', 'digest', 'firewall-export', 'notifications', 'privacy', 'webhook-events']
/** What shows the mode or the settings of checks */
const FROM_CHECKS = ['status', 'blocklists', 'notifications', 'privacy', 'signatures', 'traps']
/** What shows blocks */
const FROM_BANS = ['status', 'bans', 'detections', 'detection', 'lookup']

/**
 * The status, the checks, the protection level and the global settings,
 * as the server last sent them.
 */
export const state = reactive({
	get status(): Status | null {
		return status.data
	},
	set status(value: Status | null) {
		status.data = value
	},
	get checks(): Check[] {
		return checkList.data?.checks ?? []
	},
	set checks(value: Check[]) {
		checkList.data = { checks: value, categories: checkList.data?.categories ?? [], modes: checkList.data?.modes ?? [], severities: checkList.data?.severities ?? [] }
	},
	get categories(): Category[] {
		return checkList.data?.categories ?? []
	},
	get protectionLevel(): ProtectionLevel {
		return level.data?.level ?? 'recommended'
	},
	set protectionLevel(value: ProtectionLevel) {
		level.data = { level: value }
	},
	get settings(): GlobalSetting[] {
		return settingsPayload.data?.settings ?? []
	},
	set settings(value: GlobalSetting[]) {
		settingsPayload.data = { settings: value, templates: settingsPayload.data?.templates ?? {} }
	},
	get templates(): Record<string, string> {
		return settingsPayload.data?.templates ?? {}
	},
	set templates(value: Record<string, string>) {
		settingsPayload.data = { settings: settingsPayload.data?.settings ?? [], templates: value }
	},
	ownAddress: initial?.ownAddress ?? null,
	docUrl: initial?.docUrl ?? '',
	bruteForceSettingsUrl: initial?.bruteForceSettingsUrl ?? '',
})

/** The detection filters of the overview; other tabs set them with "Show recent detections" */
export const detectionFilters = reactive<DetectionFilters>({ check: '', severity: '', user: '', address: '', mode: '' })

/** A detection to open in the overview, from a link or another tab */
export const openDetectionId = ref<string | null>(null)

/** An incident report to build on the Incidents tab, e.g. from "Incident report for this address" */
export const incidentRequest = ref<IncidentRequest | null>(null)

/** Values, types and choices of the global settings, for `{name}` placeholders in texts */
export const globalValues = computed<Record<string, ParamValue>>(() => Object.fromEntries(state.settings.map((s) => [s.name, s.value])))
export const globalTypes = computed<Record<string, ParamType>>(() => Object.fromEntries(state.settings.map((s) => [s.name, s.type])))
export const globalChoices = computed<Record<string, Choice[]>>(() => Object.fromEntries(state.settings.map((s) => [s.name, s.choices])))

/**
 * The label of a mode, as the server sends it with the checks.
 *
 * @param mode - The mode
 */
export function modeLabel(mode: Mode): string {
	return checkList.data?.modes.find((choice) => choice.value === mode)?.label ?? mode
}

/**
 * The label of a severity, as the server sends it with the checks.
 *
 * @param severity - The severity
 */
export function severityLabel(severity: string): string {
	return checkList.data?.severities.find((choice) => choice.value === severity)?.label ?? severity
}

/** The logins that wait for an administrator, oldest first */
export const waitingLogins = computed<LoginApproval[]>({
	get: () => waiting.data ?? [],
	set: (value) => {
		waiting.data = value
	},
})

/** The waiting logins this administrator may decide: someone waits for them */
export const decidableLogins = computed(() => waitingLogins.value.filter((approval) => approval.canDecide))

/** The accounts that wait to become administrators, oldest first */
export const adminGrants = computed<AdminGrantRequest[]>({
	get: () => grants.data ?? [],
	set: (value) => {
		grants.data = value
	},
})

/** The requests for a new administrator this administrator may approve */
export const approvableGrants = computed(() => adminGrants.value.filter((request) => request.canApprove))

/** Waiting logins and new administrators are looked up this often; someone waits on the other side */
const WAITING_POLL = 30_000

/**
 * The logins that wait for an administrator; `waitingLogins` has the list.
 *
 * @param options - Resource options
 */
export function useWaitingLogins(options: ResourceOptions = {}) {
	return useResource('waiting-logins', fetchWaitingLogins, options)
}

/**
 * Keep the waiting logins and the requests for new administrators up to
 * date while the page is open, for the header and every list of them.
 */
export function useWaitingRequests(): void {
	useWaitingLogins({ poll: WAITING_POLL })
	useResource('admin-grants', fetchAdminGrants, { poll: WAITING_POLL })
}

/**
 * Approve or reject a waiting login. It leaves the list at once; the list
 * is loaded again either way, as someone else may have decided it.
 *
 * @param id - The request
 * @param approve - Approve, or reject
 */
export async function decideLogin(id: string, approve: boolean): Promise<void> {
	try {
		await (approve ? approveRequest(id) : rejectRequest(id))
		waitingLogins.value = waitingLogins.value.filter((approval) => approval.id !== id)
	} finally {
		void invalidate('waiting-logins')
	}
}

/**
 * Approve or reject a request for a new administrator, like `decideLogin`.
 *
 * @param id - The request
 * @param approve - Approve, or reject
 */
export async function decideAdminGrant(id: string, approve: boolean): Promise<void> {
	try {
		await (approve ? approveRequest(id) : rejectRequest(id))
		adminGrants.value = adminGrants.value.filter((request) => request.id !== id)
	} finally {
		void invalidate('admin-grants')
	}
}

/**
 * @param values - New values by setting name
 */
export async function saveSettings(values: Record<string, ParamValue>): Promise<void> {
	settingsPayload.data = await heldForApproval(updateSettings(values))
	await invalidate(...FROM_SETTINGS)
}

/**
 * A change that would switch off the approval of new administrators waits
 * for a second administrator: the request then shows in the list of those
 * waiting, and the failure tells why.
 *
 * @param write - The change
 */
async function heldForApproval<T>(write: Promise<T>): Promise<T> {
	try {
		return await write
	} catch (error) {
		if (error instanceof ApiError && (error.reason === 'approval_requested' || error.reason === 'no_approver')) {
			void invalidate('admin-grants')
		}
		throw error
	}
}

/**
 * Put every setting and check back to its default.
 */
export async function resetAllSettings(): Promise<void> {
	settingsPayload.data = await heldForApproval(resetSettings())
	await invalidate(...FROM_SETTINGS, ...FROM_CHECKS)
}

/**
 * @param action - Start, extend or stop learning mode
 * @param days - For start and extend
 */
export async function changeLearning(action: 'start' | 'extend' | 'stop', days?: number): Promise<void> {
	await updateLearning(action, days)
	await invalidate('status', 'checks', 'settings', 'learning-recap')
}

/**
 * @param check - The check as the server returned it
 */
function putCheck(check: Check): void {
	const checks = [...state.checks]
	const index = checks.findIndex((c) => c.id === check.id)
	if (index === -1) {
		checks.push(check)
	} else {
		checks.splice(index, 1, check)
	}
	state.checks = checks
}

/**
 * Change a check. New settings can make the protection level "custom".
 *
 * @param id - The check
 * @param change - What to change
 * @param change.mode - The new mode
 * @param change.responses - The responses to run
 * @param change.params - New setting values by name
 */
export async function saveCheck(id: string, change: { mode?: Mode, responses?: string[], params?: Record<string, ParamValue> }): Promise<Check> {
	const check = await heldForApproval(updateCheck(id, change))
	putCheck(check)
	await invalidate(...FROM_CHECKS, ...(change.params === undefined ? [] : ['protection-level']))
	return check
}

/**
 * Put a check back to its defaults.
 *
 * @param id - The check
 */
export async function resetCheckToDefaults(id: string): Promise<Check> {
	const check = await heldForApproval(resetCheck(id))
	putCheck(check)
	await invalidate(...FROM_CHECKS, 'protection-level')
	return check
}

/**
 * Set every limit to a level. The choice shows at once and is put back
 * when it cannot be saved.
 *
 * @param value - The level
 */
export async function chooseProtectionLevel(value: Exclude<ProtectionLevel, 'custom'>): Promise<void> {
	const previous = level.data
	level.data = { level: value }
	try {
		const result = await updateProtectionLevel(value)
		level.data = { level: result.level }
		checkList.data = result.checks
	} catch (error) {
		level.data = previous
		throw error
	}
	await invalidate('settings', ...FROM_CHECKS)
}

/**
 * Block an address or a network by hand.
 *
 * @param ban - The block
 * @param ban.target - Address or network
 * @param ban.level - Escalation level
 * @param ban.duration - Duration in seconds instead of the level's
 * @param ban.note - Why
 */
export async function banAdd(ban: { target: string, level: number, duration?: number, note: string }): Promise<Ban> {
	const added = await addBan(ban)
	await invalidate(...FROM_BANS)
	return added
}

/**
 * @param id - The block
 * @param note - Why it is lifted
 */
export async function banLift(id: string, note: string): Promise<Ban> {
	const lifted = await liftBan(id, note)
	await invalidate(...FROM_BANS)
	return lifted
}
