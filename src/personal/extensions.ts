/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Component } from 'vue'

import { defineAsyncComponent, shallowReactive } from 'vue'

/**
 * The parts of the personal security section, in order. Later parts of the
 * app add an entry here and the page renders it in its place; the page
 * itself is never edited for that.
 *
 * Positions are reserved for parts that come with other steps:
 * - `PERSONAL_ORDER.checklist`: the "Secure my account" checklist, which
 *   stays at the top of the section until it is done or dismissed;
 * - `PERSONAL_ORDER.securityChanges`: "Recent security changes", after the
 *   recent logins.
 *
 * A section is a card of its own. `half` sections sit next to each other on
 * wide screens; everything stacks into one column on narrow ones. Sections
 * read and refresh the shared state in `store.ts`.
 */

export interface PersonalSection {
	id: string
	order: number
	component: Component
	/** `full` (default) spans the section; two `half` sections share a row on wide screens */
	width?: 'full' | 'half'
}

export const PERSONAL_ORDER = {
	checklist: 10,
	status: 20,
	emailHint: 30,
	events: 40,
	failedLogins: 50,
	logins: 60,
	securityChanges: 70,
	knownDevices: 80,
	trustedNetworks: 90,
	logOutElsewhere: 100,
} as const

export const personalSections = shallowReactive<PersonalSection[]>([
	{ id: 'status', order: PERSONAL_ORDER.status, component: defineAsyncComponent(() => import('./components/StatusLine.vue')) },
	{ id: 'email-hint', order: PERSONAL_ORDER.emailHint, component: defineAsyncComponent(() => import('./components/EmailHint.vue')) },
	{ id: 'events', order: PERSONAL_ORDER.events, component: defineAsyncComponent(() => import('./components/SecurityEvents.vue')) },
	{ id: 'failed-logins', order: PERSONAL_ORDER.failedLogins, component: defineAsyncComponent(() => import('./components/FailedLogins.vue')) },
	{ id: 'logins', order: PERSONAL_ORDER.logins, component: defineAsyncComponent(() => import('./components/RecentLogins.vue')) },
	{ id: 'known-devices', order: PERSONAL_ORDER.knownDevices, width: 'half', component: defineAsyncComponent(() => import('./components/KnownDevices.vue')) },
	{ id: 'trusted-networks', order: PERSONAL_ORDER.trustedNetworks, width: 'half', component: defineAsyncComponent(() => import('./components/TrustedNetworks.vue')) },
	{ id: 'log-out-elsewhere', order: PERSONAL_ORDER.logOutElsewhere, component: defineAsyncComponent(() => import('./components/LogOutElsewhere.vue')) },
])

/**
 * The sections in order.
 */
export function orderedPersonalSections(): PersonalSection[] {
	return [...personalSections].sort((a, b) => a.order - b.order)
}
