/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * The shapes of the personal API, generated from `openapi-full.json`, and
 * the types only the page uses.
 */

import type { components } from '../types/openapi/openapi-full.ts'

type Schemas = components['schemas']

export type StatusItem = Schemas['PersonalStatusItem']
export type PersonalStatus = Schemas['PersonalStatus']
export type FailedLoginDay = Schemas['FailedLoginDay']
export type FailedLogins = Schemas['FailedLogins']
export type EmailHint = Schemas['EmailHint']
export type PersonalOverview = Schemas['PersonalOverview']
export type SecurityEvent = Schemas['PersonalDetection']
export type Login = Schemas['Login']
export type KnownDevice = Schemas['KnownDevice']
export type TrustedNetwork = Schemas['TrustedNetwork']
export type LoggedOutElsewhere = Schemas['LoggedOutElsewhere']
export type ActivityItem = Schemas['PersonalActivityItem']
export type PersonalActivity = Schemas['PersonalActivity']
export type StaleCredential = Schemas['StaleCredential']

export type StatusLevel = Schemas['PersonalStatus']['level']

export type Verdict = 'confirmed' | 'denied'

export type ActivityKind = Schemas['PersonalActivityItem']['kind']

/** What "Manage" has to offer */
export interface ManageSummary {
	devices: number
	networks: number
	otherBrowsers: number
}

/** What the page comes with */
export interface PersonalState {
	overview: PersonalOverview
	manage: ManageSummary
	staleCredentials: StaleCredential[]
}
