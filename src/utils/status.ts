/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Status } from '../types.ts'

import { mdiShieldCheckOutline, mdiShieldOffOutline, mdiShieldSearch } from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { APP_ID } from './format.ts'

/**
 * The icon of the protection state.
 *
 * @param state - The state
 */
export function statusIcon(state: Status['state']): string {
	return {
		protecting: mdiShieldCheckOutline,
		learning: mdiShieldSearch,
		off: mdiShieldOffOutline,
	}[state]
}

/**
 * The status in a few words, e.g. "Learning: 7 days left".
 *
 * @param status - The status
 */
export function statusTitle(status: Status): string {
	switch (status.state) {
		case 'learning':
			return n(APP_ID, 'Learning: %n day left', 'Learning: %n days left', status.learning.daysLeft)
		case 'off':
			return t(APP_ID, 'Off')
		default:
			return t(APP_ID, 'Protecting')
	}
}
