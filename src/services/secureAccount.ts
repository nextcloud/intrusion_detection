/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { AccountGuide, SecureAccount, SecureAccountProgress, SecureAccountStepId } from '../secureAccountTypes.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { generateOcsUrl, generateUrl } from '@nextcloud/router'
import { ApiError, call } from './api.ts'

/**
 * @param signal - Cancels the request
 */
export function fetchSecureAccount(signal?: AbortSignal): Promise<SecureAccount> {
	return call<SecureAccount>('get', 'personal/secure-account', { signal })
}

/**
 * @param signal - Cancels the request
 */
export function fetchSecureAccountProgress(signal?: AbortSignal): Promise<SecureAccountProgress> {
	return call<SecureAccountProgress>('get', 'personal/secure-account/progress', { signal })
}

export const startSecureAccount = () => call<SecureAccount>('post', 'personal/secure-account')

export const dismissSecureAccount = () => call<SecureAccount>('delete', 'personal/secure-account')

/**
 * @param step - A step the user checks themselves
 */
export function completeStep(step: SecureAccountStepId): Promise<SecureAccount> {
	return call<SecureAccount>('post', 'personal/secure-account/steps/' + step)
}

/**
 * Revoke a session or app password through the personal security settings, which ask for the password first.
 *
 * @param id - The token id
 */
export async function revokeSession(id: number): Promise<void> {
	await axios.delete(generateUrl('/settings/personal/authtokens/{id}', { id }), { confirmPassword: PwdConfirmationMode.Strict })
}

/**
 * Delete a share through the sharing API.
 *
 * @param id - The full share id
 */
export async function deleteShare(id: string): Promise<void> {
	await axios.delete(generateOcsUrl('apps/files_sharing/api/v1/shares/{id}', { id }))
}

/**
 * Change the password through the personal settings.
 *
 * @param oldPassword - The current password
 * @param newPassword - The new password
 */
export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
	try {
		await axios.post(generateUrl('/settings/personal/changepassword'), { oldpassword: oldPassword, newpassword: newPassword })
	} catch (error) {
		const message = isAxiosError(error) ? (error.response?.data as { data?: { message?: string } } | undefined)?.data?.message : undefined
		throw new ApiError(message ?? '', null, { cause: error })
	}
}

/**
 * @param detectionId - A detection about the account
 * @param signal - Cancels the request
 */
export function fetchAccountGuide(detectionId: number, signal?: AbortSignal): Promise<AccountGuide> {
	return call<AccountGuide>('get', 'detections/' + detectionId + '/secure-account', { signal })
}

/**
 * @param detectionId - The detection of the lock
 */
export function reenableAccount(detectionId: number): Promise<AccountGuide> {
	return call<AccountGuide>('post', 'detections/' + detectionId + '/reenable', { data: {}, confirm: true })
}

/**
 * @param detectionId - A detection about the account
 */
export function confirmPasswordReset(detectionId: number): Promise<AccountGuide> {
	return call<AccountGuide>('post', 'detections/' + detectionId + '/secure-account/password', { data: {}, confirm: true })
}
