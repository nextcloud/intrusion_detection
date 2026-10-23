/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Component } from 'vue'
import type { DetectionDetail } from './types.ts'

import { mdiCogOutline, mdiFileDocumentAlertOutline, mdiShieldCheckOutline, mdiShieldLockOutline, mdiViewDashboardOutline } from '@mdi/js'
import { defineAsyncComponent, shallowReactive } from 'vue'
import { APP_ID } from './utils/format.ts'
import { t } from './utils/l10n.ts'

/**
 * The tabs of the admin page, and the sections that join other components
 * without those knowing them: sections of check cards and of detection
 * details.
 */

export interface TabDefinition {
	id: string
	name: () => string
	icon: string
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

export const tabs: TabDefinition[] = [
	{ id: 'overview', name: () => t(APP_ID, 'Overview'), icon: mdiViewDashboardOutline, component: defineAsyncComponent(() => import('./views/OverviewTab.vue')) },
	{ id: 'protection', name: () => t(APP_ID, 'Protection'), icon: mdiShieldCheckOutline, component: defineAsyncComponent(() => import('./views/ProtectionTab.vue')) },
	{ id: 'blocks', name: () => t(APP_ID, 'Blocks'), icon: mdiShieldLockOutline, component: defineAsyncComponent(() => import('./views/BlocksTab.vue')) },
	{ id: 'settings', name: () => t(APP_ID, 'Settings'), icon: mdiCogOutline, component: defineAsyncComponent(() => import('./views/SettingsTab.vue')) },
	{ id: 'incidents', name: () => t(APP_ID, 'Incidents'), icon: mdiFileDocumentAlertOutline, component: defineAsyncComponent(() => import('./views/IncidentsTab.vue')) },
]

export const checkSections = shallowReactive<CheckSection[]>([
	{ id: 'breach-privacy', checks: ['breached_password'], after: 'data', component: defineAsyncComponent(() => import('./components/checks/BreachedPasswordPrivacy.vue')) },
	{ id: 'payload-test', checks: ['injection_probe'], after: 'wrong', component: defineAsyncComponent(() => import('./components/payload/TestUrlSection.vue')) },
	{ id: 'reserved-names', checks: ['reserved_name'], after: 'settings', component: defineAsyncComponent(() => import('./components/decoys/TrapsLinkSection.vue')), replacesParams: ['names'] },
	{ id: 'trap-paths', checks: ['trap_url'], after: 'settings', component: defineAsyncComponent(() => import('./components/decoys/TrapsLinkSection.vue')), replacesParams: ['builtin_enabled', 'autodiscover', 'paths'] },
	{ id: 'payload-signatures', checks: ['injection_probe'], after: 'data', component: defineAsyncComponent(() => import('./components/payload/SignaturesSection.vue')), replacesParams: ['disabled_signatures', 'custom_signatures'] },
	{ id: 'risky-network', checks: ['risky_network'], after: 'settings', component: defineAsyncComponent(() => import('./components/checks/RiskyNetworkSection.vue')) },
])

export const detectionSections = shallowReactive<DetectionSection[]>([
	{ id: 'secure-account', applies: (detail) => detail.detection.uid !== null, component: defineAsyncComponent(() => import('./components/overview/SecureAccountPanel.vue')) },
])
