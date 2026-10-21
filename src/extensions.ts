/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Component } from 'vue'
import type { DetectionDetail } from './types.ts'

import { mdiCogOutline, mdiFileDocumentAlertOutline, mdiShieldCheckOutline, mdiShieldLockOutline, mdiViewDashboardOutline } from '@mdi/js'
import { t } from '@nextcloud/l10n'
import { defineAsyncComponent, shallowReactive } from 'vue'
import { APP_ID } from './utils/format.ts'

/**
 * The places where later parts of the app plug into the admin page.
 *
 * - A tab: set `component` of its entry in `tabs` (or add an entry). Tabs
 *   without a component or sections are not shown, so the page never has an
 *   empty tab.
 * - A section within a tab: add an entry to `tabSections`, e.g. the risk
 *   score card on the Protection tab. Sections are rendered after the tab's own
 *   component, by `order`, so several parts of the app can fill one tab.
 * - A section in check cards: add an entry to `checkSections`, e.g. "Test a
 *   URL" for one check, rendered in the expanded card after the named section.
 * - The status banner: add a component to `statusSections`, e.g. a
 *   banner; it is rendered under the key figures.
 * - The detail of a detection: add an entry to `detectionSections`, e.g. the
 *   account's "Secure my account" progress; rendered after "What Nextcloud did".
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

export interface TabSection {
	id: string
	/** The id of the tab it is shown in */
	tab: string
	order: number
	component: Component
}

export interface CheckSection {
	id: string
	/** Check ids the section belongs to; empty for every check */
	checks: string[]
	/** The built-in section it follows */
	after: 'detects' | 'decides' | 'happens' | 'settings' | 'wrong' | 'cost' | 'data'
	/** Receives the check as prop `check` */
	component: Component
	/** Settings of the check the section edits itself, so the card's settings form leaves them out */
	replacesParams?: string[]
}

export interface DetectionSection {
	id: string
	/** Whether the section applies to this detection */
	applies: (detail: DetectionDetail) => boolean
	/** Receives the detection detail as prop `detail` */
	component: Component
}

export const tabs = shallowReactive<TabDefinition[]>([
	{ id: 'overview', name: () => t(APP_ID, 'Overview'), icon: mdiViewDashboardOutline, order: 10, component: defineAsyncComponent(() => import('./views/OverviewTab.vue')) },
	{ id: 'protection', name: () => t(APP_ID, 'Protection'), icon: mdiShieldCheckOutline, order: 20, component: defineAsyncComponent(() => import('./views/ProtectionTab.vue')) },
	{ id: 'blocks', name: () => t(APP_ID, 'Blocks'), icon: mdiShieldLockOutline, order: 30, component: defineAsyncComponent(() => import('./views/BlocksTab.vue')) },
	{ id: 'settings', name: () => t(APP_ID, 'Settings'), icon: mdiCogOutline, order: 40, component: defineAsyncComponent(() => import('./views/SettingsTab.vue')) },
	{ id: 'incidents', name: () => t(APP_ID, 'Incidents'), icon: mdiFileDocumentAlertOutline, order: 50, component: defineAsyncComponent(() => import('./views/IncidentsTab.vue')) },
])

export const checkSections = shallowReactive<CheckSection[]>([
	{ id: 'breach-privacy', checks: ['breached_password'], after: 'data', component: defineAsyncComponent(() => import('./components/checks/BreachedPasswordPrivacy.vue')) },
	{ id: 'payload-test', checks: ['injection_probe'], after: 'wrong', component: defineAsyncComponent(() => import('./components/payload/TestUrlSection.vue')) },
	{ id: 'reserved-names', checks: ['reserved_name'], after: 'settings', component: defineAsyncComponent(() => import('./components/decoys/TrapsLinkSection.vue')), replacesParams: ['names'] },
	{ id: 'trap-paths', checks: ['trap_url'], after: 'settings', component: defineAsyncComponent(() => import('./components/decoys/TrapsLinkSection.vue')), replacesParams: ['builtin_enabled', 'autodiscover', 'paths'] },
	{ id: 'payload-signatures', checks: ['injection_probe'], after: 'data', component: defineAsyncComponent(() => import('./components/payload/SignaturesSection.vue')), replacesParams: ['disabled_signatures', 'custom_signatures'] },
	{ id: 'risky-network', checks: ['risky_network'], after: 'settings', component: defineAsyncComponent(() => import('./components/checks/RiskyNetworkSection.vue')) },
])

export const tabSections = shallowReactive<TabSection[]>([
	{ id: 'risk-score', tab: 'protection', order: 10, component: defineAsyncComponent(() => import('./components/checks/RiskScoreSection.vue')) },
])

export const statusSections = shallowReactive<Component[]>([])

export const detectionSections = shallowReactive<DetectionSection[]>([
	{ id: 'secure-account', applies: (detail) => detail.detection.uid !== null, component: defineAsyncComponent(() => import('./components/overview/SecureAccountPanel.vue')) },
])

/**
 * The sections of a tab, in order.
 *
 * @param tabId - The tab
 */
export function sectionsOf(tabId: string): TabSection[] {
	return tabSections.filter((section) => section.tab === tabId).sort((a, b) => a.order - b.order)
}

/**
 * The tabs that have content, in order.
 */
export function visibleTabs(): TabDefinition[] {
	return tabs
		.filter((tab) => tab.component !== undefined || sectionsOf(tab.id).length > 0)
		.sort((a, b) => a.order - b.order)
}
