/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** One security change of an account, as the server explains it */
export interface SecurityChange {
	id: number
	type: string
	label: string
	/** self, admin, occ, reset or system */
	via: string
	actor: string | null
	previous: string | null
	new: string | null
	detail: string | null
	address: string | null
	createdAt: number
}

export type SecureAccountStepId = 'password' | 'sessions' | 'two_factor' | 'email' | 'shares' | 'files'

export interface SecureAccountStep {
	id: SecureAccountStepId
	done: boolean
	doneAt: number | null
	skipped: boolean
	/** The password is managed outside Nextcloud */
	managed: boolean
	/** The user marks this step done themselves */
	userConfirms: boolean
}

export interface SecureAccountProgress {
	active: boolean
	startedAt: number | null
	eventAt: number | null
	reason: string | null
	detectionId: number | null
	closedAt: number | null
	closedBy: string | null
	done: number
	total: number
	steps: SecureAccountStep[]
}

export interface SecureAccountSession {
	id: number
	name: string
	kind: 'session' | 'app_password'
	current: boolean
	lastActivity: number | null
	createdAt: number | null
	address: string | null
	afterEvent: boolean
}

export interface SecureAccountShare {
	/** The full share id, as the sharing API takes it */
	id: string
	name: string
	type: 'link' | 'email' | 'federated'
	recipient: string | null
	createdAt: number
	hasPassword: boolean
	expiresAt: number | null
	isFolder: boolean
}

export interface SecureAccount {
	progress: SecureAccountProgress
	since: number
	sessions: SecureAccountSession[]
	changes: SecurityChange[]
	shares: SecureAccountShare[]
	email: string | null
	canChangePassword: boolean
	links: { security: string, personalInfo: string, activity: string | null, trash: string | null }
}

/** The checklist of a detection's account, for administrators */
export interface AccountGuide {
	uid: string
	displayName: string
	exists: boolean
	enabled: boolean
	lockedByLink: boolean
	canReenable: boolean
	progress: SecureAccountProgress | null
}
