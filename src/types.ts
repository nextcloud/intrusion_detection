/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * The shapes of the admin API, generated from `openapi-full.json` (see
 * `npm run typescript:generate`), and the types only the page uses.
 */

import type { components } from './types/openapi/openapi-full.ts'

type Schemas = components['schemas']

export type Choice = Schemas['Choice']
export type Param = Schemas['Param']
export type CheckResponse = Schemas['CheckResponse']
export type Requirement = Schemas['Requirement']
export type CheckStats = Schemas['CheckStats']
export type ProtectionLevel = Schemas['ProtectionLevel']['level']
export type Check = Schemas['Check']
export type Category = Schemas['Category']
export type CheckList = Schemas['CheckList']
export type Learning = Schemas['Learning']
export type LearningRecap = Schemas['LearningRecap']
export type Problem = Schemas['Problem']
export type Status = Schemas['Status']
export type Detection = Schemas['Detection']
export type DetectionList = Schemas['DetectionList']
export type Narrative = Schemas['Narrative']
export type Attempt = Schemas['Attempt']
export type Ban = Schemas['Ban']
export type BanLimits = Schemas['BanLimits']
export type BanList = Schemas['BanList']
export type RiskPart = Schemas['RiskPart']
export type RiskLimit = Schemas['RiskLimit']
export type Risk = Schemas['Risk']
export type DetectionDetail = Schemas['DetectionDetail']
export type LookupResult = Schemas['Lookup']
export type GlobalSetting = Schemas['GlobalSetting']
export type SettingsPayload = Schemas['Settings']
export type Day = Schemas['Day']
export type DailyStats = Schemas['DailyStats']
export type DigestOverview = Schemas['Digest']
export type ModeState = Schemas['ModeState']
export type Simulation = Schemas['Simulation']
export type Snippet = Schemas['Snippet']
export type FirewallExport = Schemas['FirewallExport']
export type BlocklistDay = Schemas['BlocklistDay']
export type Blocklist = Schemas['Blocklist']
export type Blocklists = Schemas['Blocklists']
export type SyncResult = Schemas['SyncResult']
export type Decoy = Schemas['Decoy']
export type NewDecoy = Schemas['NewDecoy']
export type ReservedNames = Schemas['ReservedNames']
export type TrapPathList = Schemas['TrapPaths']
export type Traps = Schemas['Traps']
export type Recipient = Schemas['Recipient']
export type CheckNotifications = Schemas['CheckNotifications']
export type Notifications = Schemas['Notifications']
export type TestAlertResult = Schemas['TestAlert']
export type StoredData = Schemas['StoredData']
export type OutgoingData = Schemas['OutgoingData']
export type Privacy = Schemas['Privacy']
export type Signature = Schemas['Signature']
export type CustomSignature = Schemas['CustomSignature']
export type Signatures = Schemas['Signatures']
export type SignatureMatch = Schemas['SignatureMatch']
export type PayloadForm = Schemas['PayloadForm']
export type PayloadValue = Schemas['PayloadValue']
export type PayloadTest = Schemas['PayloadTest']
export type IncidentEntry = Schemas['IncidentEntry']
export type IncidentSummary = Schemas['IncidentSummary']
export type IncidentReport = Schemas['IncidentReport']
export type ConfirmationMethod = Schemas['ConfirmationMethod']
export type ConfirmationPolicy = Schemas['ConfirmationPolicy']
export type ConfirmationOutcome = Schemas['ConfirmationOutcome']
export type LoginApproval = Schemas['LoginApproval']
export type AdminGrantRequest = Schemas['AdminGrantRequest']
export type ConfirmationPresetResult = Schemas['ConfirmationPreset']
export type ConfirmationOverview = Schemas['Confirmation']
export type UnconfirmableAccount = Schemas['UnconfirmableAccount']

export type Mode = Schemas['ModeState']['configured']

export type Severity = Schemas['Detection']['severity']

export type ParamType = Schemas['Param']['type']

export type ParamValue = number | boolean | string | string[]

export type DetectionOutcome = Schemas['Detection']['outcome']

export interface DetectionFilters {
	check: string
	severity: string
	user: string
	address: string
	mode: '' | 'enforced' | 'observed'
}

export interface InitialState {
	status: Status
	checks: CheckList
	protectionLevel: ProtectionLevel
	settings: SettingsPayload
	ownAddress: string | null
	docUrl: string
	bruteForceSettingsUrl: string
}

export type CheckRef = Schemas['Traps']['decoyCheck']

export type ListPurpose = Schemas['Blocklist']['purpose']

export type DecoyFormat = 'app-password' | 'token'

export type TrapWebServer = Schemas['TrapPaths']['webServer']

export type DecoyLimits = Schemas['Traps']['limits']

export type IncidentSubjectType = 'user' | 'address'

export interface IncidentRequest {
	/** The account or the address */
	type: IncidentSubjectType
	value: string
	/** Unix times; null for the default period (the 7 days before now) */
	since: number | null
	until: number | null
}

export type ConfirmationMethodId = 'second_factor' | 'known_device' | 'email_code' | 'admin_approval'

/** The outcome of every reason at once; "custom" when they were set per reason */
export type ConfirmationPreset = 'recommended' | 'refuse' | 'allow'

/** The spec types an example payload as an object of objects; it is any JSON object */
export type WebhookEvent = Omit<Schemas['WebhookEvent'], 'example'> & { example: Record<string, unknown> }

export type WebhookEvents = Omit<Schemas['WebhookEvents'], 'events'> & { events: WebhookEvent[] }
