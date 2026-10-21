/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** Where a link on the admin page leads */
export interface LinkTarget {
	tab: string
	/** A check on the Protection tab, opened when the advanced options are on */
	check: string | null
	/** A section within the tab, scrolled to: element id `ids-section-<section>` */
	section: string | null
	/** A detection to open on the Overview */
	detection: number | null
	/** The target is only shown with the advanced options, so following it turns them on */
	advanced: boolean
}

/** The tabs of the page; `incidents` only with the advanced options */
const TABS = ['overview', 'protection', 'blocks', 'settings', 'incidents']
const ADVANCED_TABS = ['incidents']

/**
 * Tabs the page had before, and where their content is now. Emails,
 * notifications and bookmarks still carry these links.
 */
const MOVED: Record<string, { tab: string, section: string | null, advanced: boolean }> = {
	checks: { tab: 'protection', section: null, advanced: false },
	decoys: { tab: 'blocks', section: 'decoys', advanced: false },
	notifications: { tab: 'settings', section: 'notifications', advanced: false },
	confirmation: { tab: 'settings', section: 'confirmation', advanced: false },
	privacy: { tab: 'settings', section: 'privacy', advanced: false },
	advanced: { tab: 'settings', section: 'advanced', advanced: true },
}

const ID = /^[a-z][a-z0-9_-]{0,63}$/

/**
 * Resolve a link of the page, with or without "#": `#protection`,
 * `#protection/credential_stuffing`, `#settings/notifications`,
 * `#detection-42`, and the links of the former tabs such as `#checks/…`,
 * `#decoys` or `#advanced`.
 *
 * @param hash - The location hash
 * @return the target, or null for a link the page does not know
 */
export function resolveLink(hash: string): LinkTarget | null {
	const link = hash.replace(/^#/, '')
	const detection = link.match(/^detection-(\d{1,18})$/)
	if (detection) {
		return { tab: 'overview', check: null, section: null, detection: Number(detection[1]), advanced: false }
	}
	const [first = '', rest = null, ...more] = link.split('/')
	if (more.length > 0 || (rest !== null && !ID.test(rest))) {
		return null
	}
	const moved = MOVED[first]
	if (moved) {
		return {
			tab: moved.tab,
			check: moved.tab === 'protection' ? rest : null,
			section: moved.tab === 'protection' ? null : (rest ?? moved.section),
			detection: null,
			advanced: moved.advanced,
		}
	}
	if (!TABS.includes(first)) {
		return null
	}
	return {
		tab: first,
		check: first === 'protection' ? rest : null,
		section: first === 'protection' ? null : rest,
		detection: null,
		advanced: ADVANCED_TABS.includes(first),
	}
}
