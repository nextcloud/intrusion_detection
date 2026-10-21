/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { OCSResponse } from '@nextcloud/typings/ocs'
import type {
	Ban,
	BanList,
	Check,
	CheckList,
	DailyStats,
	DetectionDetail,
	DetectionFilters,
	DetectionList,
	Learning,
	LookupResult,
	Mode,
	ParamValue,
	SettingsPayload,
	Status,
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
