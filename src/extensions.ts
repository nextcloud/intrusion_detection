/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Component } from 'vue'

import { mdiBellOutline, mdiCogOutline, mdiFileDocumentAlertOutline, mdiFingerprint, mdiFormatListChecks, mdiShieldLockOutline, mdiShieldSearch, mdiTargetAccount, mdiViewDashboardOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { defineAsyncComponent, shallowReactive } from 'vue'
import { APP_ID } from './utils/format.ts'

/**
 * The places where later parts of the app plug into the admin page.
 *
 * - A tab: set `component` of its entry in `tabs` (or add an entry). Tabs
 *   without a component are not shown, so the page never has an empty tab.
 * - A section in check cards: add an entry to `checkSections`, e.g. "Test a
 *   URL" for one check, rendered in the expanded card after the named section.
 * - The status banner: add a component to `statusSections`, e.g. the lockdown
 *   banner; it is rendered under the key figures.
 * - The Blocks tab: add a component to `blocksPanels`, e.g. the firewall export.
 *
 * Components read the shared state from `store.ts`.
 */

export interface TabDefinition {
	id: string
	name: () => string
	icon: string
	order: number
	component?: Component
}

export interface CheckSection {
	id: string
	/** Check ids the section belongs to; empty for every check */
	checks: string[]
	/** The built-in section it follows */
	after: 'detects' | 'decides' | 'happens' | 'settings' | 'wrong' | 'cost' | 'data'
	/** Receives the check as prop `check` */
	component: Component
}

export const tabs = shallowReactive<TabDefinition[]>([
	{ id: 'overview', name: () => t(APP_ID, 'Overview'), icon: mdiViewDashboardOutline, order: 10, component: defineAsyncComponent(() => import('./views/OverviewTab.vue')) },
	{ id: 'checks', name: () => t(APP_ID, 'Checks'), icon: mdiFormatListChecks, order: 20, component: defineAsyncComponent(() => import('./views/ChecksTab.vue')) },
	{ id: 'blocks', name: () => t(APP_ID, 'Blocks'), icon: mdiShieldLockOutline, order: 30, component: defineAsyncComponent(() => import('./views/BlocksTab.vue')) },
	{ id: 'decoys', name: () => t(APP_ID, 'Decoys'), icon: mdiTargetAccount, order: 40 },
	{ id: 'notifications', name: () => t(APP_ID, 'Notifications'), icon: mdiBellOutline, order: 50 },
	{ id: 'privacy', name: () => t(APP_ID, 'Data and privacy'), icon: mdiFingerprint, order: 60 },
	{ id: 'confirmation', name: () => t(APP_ID, 'Confirmation'), icon: mdiShieldSearch, order: 70 },
	{ id: 'incidents', name: () => t(APP_ID, 'Incidents'), icon: mdiFileDocumentAlertOutline, order: 80 },
	{ id: 'advanced', name: () => t(APP_ID, 'Advanced'), icon: mdiCogOutline, order: 90, component: defineAsyncComponent(() => import('./views/AdvancedTab.vue')) },
])

export const checkSections = shallowReactive<CheckSection[]>([])

export const statusSections = shallowReactive<Component[]>([])

export const blocksPanels = shallowReactive<Component[]>([])

/**
 * The tabs that have content, in order.
 */
export function visibleTabs(): TabDefinition[] {
	return tabs.filter((tab) => tab.component !== undefined).sort((a, b) => a.order - b.order)
}
