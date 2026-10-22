/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { ResourceOptions } from '../composables/useResource.ts'
import type { SecureAccount, SecureAccountStepId } from '../secureAccountTypes.ts'

import { invalidate, update, useResource } from '../composables/useResource.ts'
import {
	changePassword,
	completeStep,
	deleteShare,
	dismissSecureAccount,
	fetchSecureAccount,
	revokeSession,
	startSecureAccount,
} from '../services/secureAccount.ts'

/**
 * The "Secure my account" checklist of the user.
 *
 * @param options - Resource options
 */
export function useSecureAccount(options: ResourceOptions = {}) {
	return useResource('secure-account', fetchSecureAccount, options)
}

/**
 * Run a change and show the checklist as it is afterwards: as the change
 * returned it, or loaded again.
 *
 * @param change - The change
 */
async function apply(change: () => Promise<SecureAccount | void>): Promise<void> {
	const result = await change()
	if (result) {
		update<SecureAccount>('secure-account', () => result)
	} else {
		await invalidate('secure-account')
	}
}

export const startChecklist = () => apply(startSecureAccount)

export const dismissChecklist = () => apply(dismissSecureAccount)

/**
 * @param step - A step the user checked themselves
 */
export const completeChecklistStep = (step: SecureAccountStepId) => apply(() => completeStep(step))

/**
 * @param oldPassword - The current password
 * @param newPassword - The new password
 */
export const changeAccountPassword = (oldPassword: string, newPassword: string) => apply(() => changePassword(oldPassword, newPassword))

/**
 * @param id - The session or app password
 */
export const revokeAccountSession = (id: number) => apply(() => revokeSession(id))

/**
 * @param id - The full share id
 */
export const deleteAccountShare = (id: string) => apply(() => deleteShare(id))
