/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { OCSResponse } from '@nextcloud/typings/ocs'
import type {
	Ban,
	BanList,
	Blocklist,
	Blocklists,
	Check,
	CheckList,
	Contribution,
	CustomSignature,
	DailyStats,
	DecoyFormat,
	DetectionDetail,
	DetectionFilters,
	DetectionList,
	DigestOverview,
	FirewallExport,
	Learning,
	LookupResult,
	Mode,
	NewDecoy,
	Notifications,
	ParamValue,
	PayloadTest,
	Privacy,
	ReservedNames,
	SettingsPayload,
	Signatures,
	Simulation,
	Status,
	SyncResult,
	TestAlertResult,
	TrapPathList,
	Traps,
	WebhookEvents,
} from '../types.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { PasswordConfirmationCancelledError, PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { generateOcsUrl } from '@nextcloud/router'

/**
 * An error the API explained: the translated message, and the setting it is about.
 */
export class ApiError extends Error {
	constructor(
		message: string,
		public readonly param: string | null = null,
		options?: ErrorOptions,
	) {
		super(message, options)
	}
}

/**
 * Whether the admin closed the password dialog: nothing went wrong, nothing was changed.
 *
 * @param error - The error a write threw
 */
export function isCancelled(error: unknown): boolean {
	return error instanceof PasswordConfirmationCancelledError
}

/**
 * The message to show for a failed request.
 *
 * @param error - The error
 * @param fallback - What to say when the server did not explain it
 */
export function errorMessage(error: unknown, fallback: string): string {
	return error instanceof ApiError ? error.message : fallback
}

/** Writes need a recent password confirmation; the page asks for it when needed. */
const write = { confirmPassword: PwdConfirmationMode.Lax }

/**
 * @param path - Path below the app's API
 */
function url(path: string): string {
	return generateOcsUrl('apps/intrusion_detection/api/v1/' + path)
}

/**
 * Run a request and unwrap the OCS envelope; errors become `ApiError` where the server explained them.
 *
 * @param request - The request
 */
async function call<T>(request: Promise<{ data: OCSResponse<T> }>): Promise<T> {
	try {
		const { data } = await request
		return data.ocs.data
	} catch (error) {
		if (isAxiosError(error) && error.response?.data?.ocs) {
			const ocs = (error.response.data as OCSResponse<{ message?: string, param?: string | null }>).ocs
			const message = ocs.data?.message || ocs.meta.message
			if (message) {
				throw new ApiError(message, ocs.data?.param ?? null, { cause: error })
			}
		}
		throw error
	}
}

export const fetchStatus = () => call<Status>(axios.get(url('status')))

export const fetchChecks = () => call<CheckList>(axios.get(url('checks')))

/**
 * @param id - The check id
 * @param change - What to change
 * @param change.mode - The new mode
 * @param change.responses - The responses to run
 * @param change.params - New setting values by name
 */
export function updateCheck(id: string, change: { mode?: Mode, responses?: string[], params?: Record<string, ParamValue> }): Promise<Check> {
	return call<Check>(axios.put(url('checks/' + encodeURIComponent(id)), change, write))
}

/**
 * @param id - The check id
 */
export function resetCheck(id: string): Promise<Check> {
	return call<Check>(axios.post(url('checks/' + encodeURIComponent(id) + '/reset'), {}, write))
}

/**
 * @param filters - The filters
 * @param limit - Page size
 * @param offset - Page start
 * @param since - Only detections since this Unix time
 */
export function fetchDetections(filters: Partial<DetectionFilters>, limit = 25, offset = 0, since = 0): Promise<DetectionList> {
	return call<DetectionList>(axios.get(url('detections'), { params: { ...filters, limit, offset, since } }))
}

/**
 * @param id - The detection id
 */
export function fetchDetection(id: number): Promise<DetectionDetail> {
	return call<DetectionDetail>(axios.get(url('detections/' + id)))
}

/**
 * @param days - How many days
 */
export function fetchDailyStats(days = 30): Promise<DailyStats> {
	return call<DailyStats>(axios.get(url('stats/daily'), { params: { days } }))
}

/**
 * @param all - Also ended and lifted blocks
 * @param limit - Page size
 * @param offset - Page start
 */
export function fetchBans(all = false, limit = 50, offset = 0): Promise<BanList> {
	return call<BanList>(axios.get(url('bans'), { params: { all: all ? 1 : 0, limit, offset } }))
}

/**
 * @param ban - The block to add
 * @param ban.target - Address or network
 * @param ban.level - Escalation level
 * @param ban.duration - Duration in seconds instead of the level's
 * @param ban.note - Why
 */
export function addBan(ban: { target: string, level: number, duration?: number, note: string }): Promise<Ban> {
	return call<Ban>(axios.post(url('bans'), ban, write))
}

/**
 * @param id - The block id
 * @param note - Why it is lifted
 */
export function liftBan(id: number, note: string): Promise<Ban> {
	return call<Ban>(axios.delete(url('bans/' + id), { data: { note }, ...write }))
}

/**
 * @param q - A reference, an address or an account
 */
export function lookup(q: string): Promise<LookupResult> {
	return call<LookupResult>(axios.get(url('lookup'), { params: { q } }))
}

/**
 * @param action - What to do
 * @param days - For start and extend
 */
export function updateLearning(action: 'start' | 'extend' | 'stop', days = 7): Promise<Learning> {
	return call<Learning>(axios.put(url('learning'), { action, days }, write))
}

export const fetchSettings = () => call<SettingsPayload>(axios.get(url('settings')))

/**
 * @param values - New values by setting name
 */
export function updateSettings(values: Record<string, ParamValue>): Promise<SettingsPayload> {
	return call<SettingsPayload>(axios.put(url('settings'), { values }, write))
}

export const resetSettings = () => call<SettingsPayload>(axios.post(url('settings/reset'), {}, write))

export const exportSettings = () => call<Record<string, unknown>>(axios.get(url('settings/export')))

export const fetchDigest = () => call<DigestOverview>(axios.get(url('digest')))

export const sendTestDigest = () => call<{ message: string }>(axios.post(url('digest/test'), {}, write))

export const fetchWebhookEvents = () => call<WebhookEvents>(axios.get(url('events')))

/**
 * @param id - The check id
 */
export function simulateCheck(id: string): Promise<Simulation> {
	return call<Simulation>(axios.get(url('checks/' + encodeURIComponent(id) + '/simulation')))
}

export const fetchExport = () => call<FirewallExport>(axios.get(url('export')))

export const fetchBlocklists = () => call<Blocklists>(axios.get(url('blocklists')))

/**
 * @param list - The new list
 * @param list.id - Its short name
 * @param list.url - Where to download it
 * @param list.purpose - Block, or mark as hosting or Tor
 * @param list.format - The file format
 * @param list.mode - For blocklists: observe or protect
 */
export function createBlocklist(list: { id: string, url: string, purpose: string, format: string, mode: string }): Promise<Blocklist> {
	const { format, ...rest } = list
	// "format" would choose the OCS response format
	return call<Blocklist>(axios.post(url('blocklists'), { ...rest, fileFormat: format }, write))
}

/**
 * @param id - The list
 * @param change - What to change
 * @param change.enabled - Use the list
 * @param change.mode - Observe or protect
 * @param change.interval - Seconds between downloads, 0 for the default
 */
export function updateBlocklist(id: string, change: { enabled?: boolean, mode?: string, interval?: number }): Promise<Blocklist> {
	return call<Blocklist>(axios.put(url('blocklists/' + encodeURIComponent(id)), change, write))
}

/**
 * @param id - The list
 */
export function removeBlocklist(id: string): Promise<{ removed: string }> {
	return call<{ removed: string }>(axios.delete(url('blocklists/' + encodeURIComponent(id)), write))
}

/**
 * @param id - The list
 */
export function syncBlocklist(id: string): Promise<{ result: SyncResult, list: Blocklist }> {
	return call<{ result: SyncResult, list: Blocklist }>(axios.post(url('blocklists/' + encodeURIComponent(id) + '/sync'), {}, write))
}

export const fetchTraps = () => call<Traps>(axios.get(url('decoys')))

/**
 * @param decoy - The decoy to create
 * @param decoy.label - Where it is planted
 * @param decoy.loginName - An optional login name no account uses
 * @param decoy.format - What the secret looks like
 */
export function createDecoy(decoy: { label: string, loginName: string, format: DecoyFormat }): Promise<NewDecoy> {
	// "format" would choose the OCS response format
	return call<NewDecoy>(axios.post(url('decoys'), { label: decoy.label, loginName: decoy.loginName, secretFormat: decoy.format }, write))
}

/**
 * @param id - The decoy
 */
export function deleteDecoy(id: number): Promise<{ deleted: number }> {
	return call<{ deleted: number }>(axios.delete(url('decoys/' + id), write))
}

/**
 * @param change - Names to reserve and to release
 * @param change.add - Names to reserve
 * @param change.remove - Names to release
 */
export function updateReservedNames(change: { add?: string[], remove?: string[] }): Promise<ReservedNames> {
	return call<ReservedNames>(axios.put(url('reserved-names'), change, write))
}

/**
 * @param change - What to change
 * @param change.add - Paths to add
 * @param change.remove - Paths to remove
 * @param change.builtinEnabled - Use the built-in list
 * @param change.autodiscover - Trap the autodiscover path
 */
export function updateTrapPaths(change: { add?: string[], remove?: string[], builtinEnabled?: boolean, autodiscover?: boolean }): Promise<TrapPathList> {
	return call<TrapPathList>(axios.put(url('trap-paths'), change, write))
}

export const fetchNotifications = () => call<Notifications>(axios.get(url('notifications')))

export const sendTestAlert = () => call<TestAlertResult>(axios.post(url('notifications/test'), {}, write))

export const fetchPrivacy = () => call<Privacy>(axios.get(url('privacy')))

/**
 * @param change - What to change
 * @param change.enabled - Send reports
 * @param change.url - Where to send them
 */
export function updateContribution(change: { enabled?: boolean, url?: string }): Promise<Contribution> {
	return call<Contribution>(axios.put(url('contribution'), change, write))
}

export const fetchSignatures = () => call<Signatures>(axios.get(url('payload/signatures')))

/**
 * @param entries - Custom signatures to check before saving
 */
export function checkSignatures(entries: string[]): Promise<{ entries: CustomSignature[] }> {
	return call<{ entries: CustomSignature[] }>(axios.post(url('payload/signatures/check'), { entries }))
}

/**
 * @param input - A URL or a value
 */
export function testPayload(input: string): Promise<PayloadTest> {
	return call<PayloadTest>(axios.post(url('payload/test'), { input }))
}
