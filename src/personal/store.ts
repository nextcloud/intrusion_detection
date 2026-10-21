/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { PersonalOverview, PersonalState } from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { reactive } from 'vue'
import { logger } from '../services/logger.ts'
import { APP_ID } from '../utils/format.ts'
import { fetchOverview } from './api.ts'

/**
 * State the sections of the personal page share: the overview at the top,
 * which answers and logouts change, and counters that tell lists to reload.
 */
export const personal = reactive({
	overview: null as PersonalOverview | null,
	knownDevicesEnabled: true,
	/** Raised when remembered devices changed elsewhere on the page */
	devicesVersion: 0,
	/** Raised when trusted networks changed elsewhere on the page */
	networksVersion: 0,
})

/**
 * Take the state the page came with.
 */
export function initPersonalState(): void {
	const state = loadState<PersonalState | null>(APP_ID, 'personal', null)
	if (state !== null) {
		personal.overview = state.overview
		personal.knownDevicesEnabled = state.knownDevicesEnabled
	}
}

/**
 * Load the overview again, after something changed what it says.
 */
export async function refreshOverview(): Promise<void> {
	try {
		personal.overview = await fetchOverview()
	} catch (error) {
		logger.error('Could not reload the security overview', { error })
	}
}
