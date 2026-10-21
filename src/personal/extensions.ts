/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Component } from 'vue'

import { defineAsyncComponent, shallowReactive } from 'vue'

/**
 * The parts of the personal security section, top to bottom. A part that
 * has nothing to say renders nothing, and the page then gives it no room.
 * Parts read and refresh the shared state in `store.ts`.
 */
export interface PersonalSection {
	id: string
	component: Component
}

export const personalSections = shallowReactive<PersonalSection[]>([
	/** "Secure my account", on top while a checklist is open */
	{ id: 'secure-account', component: defineAsyncComponent(() => import('./components/SecureAccountCard.vue')) },
	{ id: 'status', component: defineAsyncComponent(() => import('./components/StatusLine.vue')) },
	{ id: 'email-hint', component: defineAsyncComponent(() => import('./components/EmailHint.vue')) },
	{ id: 'questions', component: defineAsyncComponent(() => import('./components/OpenQuestions.vue')) },
	{ id: 'activity', component: defineAsyncComponent(() => import('./components/ActivityTimeline.vue')) },
	{ id: 'manage', component: defineAsyncComponent(() => import('./components/ManageSection.vue')) },
])
