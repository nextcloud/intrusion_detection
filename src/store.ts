/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Category, Check, DetectionFilters, GlobalSetting, InitialState, ParamType, ParamValue, Status } from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { computed, reactive, ref } from 'vue'
import { fetchChecks, fetchSettings, fetchStatus } from './services/api.ts'
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
	settings: initial?.settings.settings ?? [] as GlobalSetting[],
	templates: initial?.settings.templates ?? {} as Record<string, string>,
	ownAddress: initial?.ownAddress ?? null,
	docUrl: initial?.docUrl ?? '',
	bruteForceSettingsUrl: initial?.bruteForceSettingsUrl ?? '',
})

export const detectionFilters = reactive<DetectionFilters>({ check: '', severity: '', user: '', address: '', mode: '' })

/** A detection to open in the overview, from a link or another tab */
export const openDetectionId = ref<number | null>(null)

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
 * Put a check as the server returned it in place of the old one.
 *
 * @param check - The check from the server
 */
export function replaceCheck(check: Check): void {
	const index = state.checks.findIndex((c) => c.id === check.id)
	if (index === -1) {
		state.checks.push(check)
	} else {
		state.checks.splice(index, 1, check)
	}
}
