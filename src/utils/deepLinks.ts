/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** Where a link on the admin page leads */
export interface LinkTarget {
	tab: string
	/** A check on the Protection tab, opened with its settings */
	check: string | null
	/** The element id of a section within the tab, scrolled to, e.g. `settings-privacy` */
	section: string | null
	/** A detection to open on the Overview */
	detection: number | null
}

/** The tabs of the page */
const TABS = ['overview', 'protection', 'blocks', 'settings', 'incidents']

/**
 * Tabs and sections the page had before, and where their content is now.
 * Emails, notifications and bookmarks still carry these links.
 */
const MOVED: Record<string, string> = {
	checks: 'protection',
	decoys: 'blocks-decoys',
	notifications: 'settings-notifications',
	confirmation: 'settings-confirmation',
	approvals: 'settings-approvals',
	accounts: 'settings-confirmation-accounts',
	privacy: 'settings-privacy',
	advanced: 'settings-learning',
}

const CHECK = /^[a-z][a-z0-9_]{0,63}$/
const SECTION = /^([a-z]+)-[a-z0-9-]{1,64}$/

/**
 * Resolve a link of the page, with or without "#":
 *
 * - a tab: `#protection`, `#incidents`;
 * - a section, by its element id: `#settings-privacy`, `#blocks-decoys`;
 * - a check: `#protection/credential_stuffing`;
 * - a detection: `#detection-42`;
 * - the links of the former tabs, such as `#checks/…`, `#decoys` or `#advanced`.
 *
 * @param hash - The location hash
 * @return the target, or null for a link the page does not know
 */
export function resolveLink(hash: string): LinkTarget | null {
	let link = hash.replace(/^#/, '')
	const detection = link.match(/^detection-(\d{1,18})$/)
	if (detection) {
		return { tab: 'overview', check: null, section: null, detection: Number(detection[1]) }
	}
	const [first = '', check = null, ...more] = link.split('/')
	link = MOVED[first] ?? first
	if (link === 'protection' && more.length === 0 && (check === null || CHECK.test(check))) {
		return { tab: 'protection', check, section: null, detection: null }
	}
	if (check !== null) {
		return null
	}
	const section = link.match(SECTION)
	const tab = section ? section[1]! : link
	if (!TABS.includes(tab)) {
		return null
	}
	return {
		tab,
		check: null,
		section: section ? link : null,
		detection: null,
	}
}
