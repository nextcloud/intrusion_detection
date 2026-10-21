/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Category, Check, DetectionFilters, GlobalSetting, IncidentRequest, InitialState, ParamType, ParamValue, ProtectionLevel, Status } from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { computed, reactive, ref } from 'vue'
import { fetchChecks, fetchProtectionLevel, fetchSettings, fetchStatus } from './services/api.ts'
import { logger } from './services/logger.ts'
import { APP_ID } from './utils/format.ts'

/**
 * The state the tabs of the admin page share: the status, the checks and
 * the global settings, plus the detection filters the overview applies
 * (other tabs set them with "Show recent detections").
 */
const initial = loadState<InitialState | null>(APP_ID, 'admin', null)

export const state = reactive({
	status: initial?.status ?? null as Status | null,
	checks: initial?.checks.checks ?? [] as Check[],
	categories: initial?.checks.categories ?? [] as Category[],
	protectionLevel: initial?.protectionLevel ?? 'recommended' as ProtectionLevel,
	settings: initial?.settings.settings ?? [] as GlobalSetting[],
	templates: initial?.settings.templates ?? {} as Record<string, string>,
	ownAddress: initial?.ownAddress ?? null,
	docUrl: initial?.docUrl ?? '',
	bruteForceSettingsUrl: initial?.bruteForceSettingsUrl ?? '',
})

export const detectionFilters = reactive<DetectionFilters>({ check: '', severity: '', user: '', address: '', mode: '' })

/** A detection to open in the overview, from a link or another tab */
export const openDetectionId = ref<number | null>(null)

/** An incident report to build on the Incidents tab, e.g. from "Incident report for this address" */
export const incidentRequest = ref<IncidentRequest | null>(null)

const ADVANCED_KEY = APP_ID + '.advanced'

/**
 * Read the remembered choice; storage can be missing or blocked.
 */
function loadAdvanced(): boolean {
	try {
		return window.localStorage.getItem(ADVANCED_KEY) === '1'
	} catch {
		return false
	}
}

/**
 * Whether the admin page shows the advanced options: the fine control of
 * each check, the expert tools and the Incidents tab. Remembered per browser.
 */
export const advanced = ref<boolean>(loadAdvanced())

/**
 * Show or hide the advanced options and remember the choice in this browser.
 *
 * @param value - Show them
 */
export function setAdvanced(value: boolean): void {
	advanced.value = value
	try {
		window.localStorage.setItem(ADVANCED_KEY, value ? '1' : '0')
	} catch {
		// Not remembered, but still applied for this page view.
	}
}

/** Values and types of the global settings, for `{name}` placeholders in texts */
export const globalValues = computed<Record<string, ParamValue>>(() => Object.fromEntries(state.settings.map((s) => [s.name, s.value])))
export const globalTypes = computed<Record<string, ParamType>>(() => Object.fromEntries(state.settings.map((s) => [s.name, s.type])))

/**
 * Reload the status banner, for example after a block was added or lifted.
 */
export async function refreshStatus(): Promise<void> {
	try {
		state.status = await fetchStatus()
	} catch (error) {
		logger.error('Could not reload the intrusion detection status', { error })
	}
}

/**
 * Reload every check, for example after all settings were reset.
 */
export async function refreshChecks(): Promise<void> {
	const list = await fetchChecks()
	state.checks = list.checks
	state.categories = list.categories
}

/**
 * Reload the global settings.
 */
export async function refreshSettings(): Promise<void> {
	const payload = await fetchSettings()
	state.settings = payload.settings
	state.templates = payload.templates
}

/**
 * Reload the protection level, which a limit changed by hand makes "custom".
 */
export async function refreshProtectionLevel(): Promise<void> {
	try {
		state.protectionLevel = (await fetchProtectionLevel()).level
	} catch (error) {
		logger.error('Could not reload the protection level', { error })
	}
}

/**
 * Put a check as the server returned it in place of the old one. When its
 * settings changed, the protection level may have become "custom".
 *
 * @param check - The check from the server
 */
export function replaceCheck(check: Check): void {
	const index = state.checks.findIndex((c) => c.id === check.id)
	const values = (c: Check | undefined) => JSON.stringify(c?.params.map((p) => p.value) ?? [])
	const paramsChanged = index !== -1 && values(state.checks[index]) !== values(check)
	if (index === -1) {
		state.checks.push(check)
	} else {
		state.checks.splice(index, 1, check)
	}
	if (paramsChanged && state.protectionLevel !== 'custom') {
		refreshProtectionLevel()
	}
}
