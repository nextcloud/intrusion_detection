/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Status } from '../types.ts'

import { mdiShieldCheckOutline, mdiShieldOffOutline, mdiShieldSearch } from '@mdi/js'

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
