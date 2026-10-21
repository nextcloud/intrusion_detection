/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
	mdiAccountCheckOutline,
	mdiAccountCogOutline,
	mdiKeyOutline,
	mdiLockAlertOutline,
	mdiLockOpenVariantOutline,
	mdiLoginVariant,
	mdiShareVariantOutline,
	mdiShieldAlertOutline,
	mdiShieldEditOutline,
	mdiShieldLockOutline,
	mdiTimelineClockOutline,
} from '@mdi/js'

/**
 * The icon of each kind of timeline entry. The server names the kinds and
 * their labels; kinds without an icon here get a neutral one.
 */
const ICONS: Record<string, string> = {
	detection: mdiShieldAlertOutline,
	block: mdiShieldLockOutline,
	block_lifted: mdiLockOpenVariantOutline,
	app_password: mdiKeyOutline,
	admin_change: mdiAccountCogOutline,
	approval: mdiAccountCheckOutline,
	share: mdiShareVariantOutline,
	login: mdiLoginVariant,
	security_change: mdiShieldEditOutline,
	lockdown: mdiLockAlertOutline,
}

/**
 * @param kind - The kind of entry
 */
export function kindIcon(kind: string): string {
	return ICONS[kind] ?? mdiTimelineClockOutline
}
