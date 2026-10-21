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
	ConfirmationOverview,
	ConfirmationPreset,
	ConfirmationPresetResult,
	CustomSignature,
	DailyStats,
	DecoyFormat,
	DetectionDetail,
	DetectionFilters,
	DetectionList,
	DigestOverview,
	FirewallExport,
	IncidentReport,
	IncidentRequest,
	Learning,
	LoginApproval,
	LookupResult,
	Mode,
	NewDecoy,
	Notifications,
	ParamValue,
	PayloadTest,
	Privacy,
	ProtectionLevel,
	ReservedNames,
	SettingsPayload,
	Signatures,
	Simulation,
	Status,
	SyncResult,
	TestAlertResult,
	TrapPathList,
	Traps,
	UnconfirmableAccount,
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
 * Whether the server refused the request because too many came in a short time.
 *
 * @param error - The error a request threw
 */
export function isRateLimited(error: unknown): boolean {
	const cause = error instanceof ApiError ? error.cause : error
	return isAxiosError(cause) && cause.response?.status === 429
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
export const write = { confirmPassword: PwdConfirmationMode.Lax }

/**
 * @param path - Path below the app's API
 */
export function url(path: string): string {
	return generateOcsUrl('apps/intrusion_detection/api/v1/' + path)
}

/**
 * Run a request and unwrap the OCS envelope; errors become `ApiError` where the server explained them.
 *
 * @param request - The request
 */
export async function call<T>(request: Promise<{ data: OCSResponse<T> }>): Promise<T> {
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

export const fetchProtectionLevel = () => call<{ level: ProtectionLevel }>(axios.get(url('protection-level')))

/**
 * Set every check limit and block duration to a level.
 *
 * @param level - The level
 */
export function updateProtectionLevel(level: Exclude<ProtectionLevel, 'custom'>): Promise<{ level: ProtectionLevel, checks: CheckList }> {
	return call<{ level: ProtectionLevel, checks: CheckList }>(axios.put(url('protection-level'), { level }, write))
}

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

/**
 * The parameters of an incident report request.
 *
 * @param request - Subject and period
 */
function incidentParams(request: IncidentRequest): Record<string, string | number> {
	const params: Record<string, string | number> = request.type === 'user' ? { user: request.value } : { address: request.value }
	if (request.since !== null) {
		params.since = request.since
	}
	if (request.until !== null) {
		params.until = request.until
	}
	return params
}

/**
 * Build an incident report to show on the page. Needs a recent password confirmation.
 *
 * @param request - Subject and period
 */
export function buildIncidentReport(request: IncidentRequest): Promise<IncidentReport> {
	return call<IncidentReport>(axios.post(url('incidents/report'), incidentParams(request), write))
}

/**
 * The incident report as a document: the server answers with the file itself.
 * Needs a recent password confirmation, like building the report.
 *
 * @param request - Subject and period
 * @param output - JSON, or the printable HTML page
 */
export async function downloadIncidentReport(request: IncidentRequest, output: 'json' | 'html'): Promise<{ blob: Blob, filename: string }> {
	try {
		const response = await axios.post<Blob>(url('incidents/report/download'), { ...incidentParams(request), output }, { ...write, responseType: 'blob' })
		const disposition = String(response.headers['content-disposition'] ?? '')
		const match = disposition.match(/filename="?([^";]+)"?/)
		return { blob: response.data, filename: match?.[1] ?? 'incident-report.' + output }
	} catch (error) {
		// Errors arrive as a blob too; read the OCS message out of it.
		if (isAxiosError(error) && error.response?.data instanceof Blob) {
			try {
				const ocs = JSON.parse(await error.response.data.text())?.ocs
				const message = ocs?.data?.message || ocs?.meta?.message
				if (message) {
					throw new ApiError(message, ocs?.data?.param ?? null, { cause: error })
				}
			} catch (parsed) {
				if (parsed instanceof ApiError) {
					throw parsed
				}
			}
		}
		throw error
	}
}

/**
 * Accounts whose name, display name or email address contains a text, for
 * the account picker. Uses the provisioning API, which administrators may use.
 *
 * @param search - What was typed
 */
export async function searchAccounts(search: string): Promise<{ uid: string, displayName: string, email: string | null }[]> {
	const { data } = await axios.get<OCSResponse<{ users: Record<string, { id: string, displayname?: string, email?: string | null }> | [] }>>(generateOcsUrl('cloud/users/details'), { params: { search, limit: 10 } })
	return Object.values(data.ocs.data.users ?? {}).map((user) => ({ uid: user.id, displayName: user.displayname || user.id, email: user.email ?? null }))
}

/**
 * @param refresh - Count the accounts again instead of using the counts of the last hour
 */
export function fetchConfirmation(refresh = false): Promise<ConfirmationOverview> {
	return call<ConfirmationOverview>(axios.get(url('confirmation'), { params: refresh ? { refresh: 1 } : {} }))
}

/**
 * The logins that wait for an administrator, read live.
 */
export function fetchWaitingLogins(): Promise<LoginApproval[]> {
	return call<LoginApproval[]>(axios.get(url('confirmation/waiting')))
}

/**
 * Set what happens to every login that nothing can confirm, for all reasons at once.
 *
 * @param preset - recommended, refuse or allow
 */
export function setConfirmationPreset(preset: ConfirmationPreset): Promise<ConfirmationPresetResult> {
	return call<ConfirmationPresetResult>(axios.put(url('confirmation/preset'), { preset }, write))
}

/**
 * @param limit - At most this many
 * @param after - The account the previous page ended with; empty for the first page
 * @param admins - Only administrators
 */
export function fetchUnconfirmableAccounts(limit = 50, after = '', admins = false): Promise<UnconfirmableAccount[]> {
	return call<UnconfirmableAccount[]>(axios.get(url('confirmation/accounts'), { params: { limit, after, admins: admins ? 1 : 0 } }))
}

/**
 * Approve a request: for a login, the waiting login continues.
 *
 * @param id - The request
 */
export function approveRequest(id: number): Promise<unknown> {
	return call<unknown>(axios.post(url(`approvals/${id}/approve`), {}, write))
}

/**
 * Reject a request: for a login, the waiting login ends.
 *
 * @param id - The request
 */
export function rejectRequest(id: number): Promise<unknown> {
	return call<unknown>(axios.post(url(`approvals/${id}/reject`), {}, write))
}
