/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ManageSummary, PersonalActivity, PersonalOverview, PersonalState } from './types.ts'

import { loadState } from '@nextcloud/initial-state'
import { t } from '@nextcloud/l10n'
import { reactive } from 'vue'
import { errorMessage } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import { APP_ID } from '../utils/format.ts'
import { fetchActivity, fetchOverview } from './api.ts'

/** Timeline entries loaded first, and added by each "Show more" */
export const ACTIVITY_PAGE = 20
/** The server's bound */
export const ACTIVITY_MAX = 100

/**
 * State the sections of the personal page share: the overview at the top
 * and the activity, which answers and logouts change, and counters that
 * tell lists to reload.
 */
export const personal = reactive({
	overview: null as PersonalOverview | null,
	manage: { devices: 0, networks: 0, otherBrowsers: 0 } as ManageSummary,
	/** The open questions and the timeline; null until loaded */
	activity: null as PersonalActivity | null,
	activityError: null as string | null,
	activityLimit: ACTIVITY_PAGE,
	activityLoading: false,
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
		personal.manage = state.manage
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

/**
 * Load the open questions and the timeline; the previous ones stay
 * visible while they reload.
 *
 * @param limit - How many timeline entries
 */
export async function loadActivity(limit = personal.activityLimit): Promise<void> {
	const bounded = Math.min(limit, ACTIVITY_MAX)
	personal.activityLoading = true
	try {
		personal.activity = await fetchActivity(bounded)
		personal.activityLimit = bounded
		personal.activityError = null
	} catch (error) {
		logger.error('Could not load the recent activity', { error })
		personal.activityError = errorMessage(error, t(APP_ID, 'Your recent activity could not be loaded. Please try again.'))
	} finally {
		personal.activityLoading = false
	}
}
