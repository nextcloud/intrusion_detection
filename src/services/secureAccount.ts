/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { OCSResponse } from '@nextcloud/typings/ocs'
import type { AccountGuide, SecureAccount, SecureAccountStepId, SecurityChange } from '../secureAccountTypes.ts'

import axios, { isAxiosError } from '@nextcloud/axios'
import { PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { generateOcsUrl, generateUrl } from '@nextcloud/router'
import { ApiError } from './api.ts'

/**
 * @param path - Path below the app's API
 */
function url(path: string): string {
	return generateOcsUrl('apps/intrusion_detection/api/v1/' + path)
}

/**
 * Run an OCS request and unwrap the envelope; errors the server explained become `ApiError`.
 *
 * @param request - The request
 */
async function call<T>(request: Promise<{ data: OCSResponse<T> }>): Promise<T> {
	try {
		const { data } = await request
		return data.ocs.data
	} catch (error) {
		if (isAxiosError(error) && error.response?.data?.ocs) {
			const ocs = (error.response.data as OCSResponse<{ message?: string }>).ocs
			const message = ocs.data?.message || ocs.meta.message
			if (message) {
				throw new ApiError(message, null, { cause: error })
			}
		}
		throw error
	}
}

export const fetchSecureAccount = () => call<SecureAccount>(axios.get(url('personal/secure-account')))

export const startSecureAccount = () => call<SecureAccount>(axios.post(url('personal/secure-account')))

export const dismissSecureAccount = () => call<SecureAccount>(axios.delete(url('personal/secure-account')))

/**
 * @param step - A step the user checks themselves
 */
export function completeStep(step: SecureAccountStepId): Promise<SecureAccount> {
	return call<SecureAccount>(axios.post(url('personal/secure-account/steps/' + step)))
}

/**
 * @param limit - At most this many, newest first
 */
export function fetchSecurityChanges(limit = 50): Promise<SecurityChange[]> {
	return call<SecurityChange[]>(axios.get(url('personal/security-changes'), { params: { limit } }))
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
 */
export function fetchAccountGuide(detectionId: number): Promise<AccountGuide> {
	return call<AccountGuide>(axios.get(url('detections/' + detectionId + '/secure-account')))
}

/**
 * @param detectionId - The detection of the lock
 */
export function reenableAccount(detectionId: number): Promise<AccountGuide> {
	return call<AccountGuide>(axios.post(url('detections/' + detectionId + '/reenable'), {}, { confirmPassword: PwdConfirmationMode.Lax }))
}

/**
 * @param detectionId - A detection about the account
 */
export function confirmPasswordReset(detectionId: number): Promise<AccountGuide> {
	return call<AccountGuide>(axios.post(url('detections/' + detectionId + '/secure-account/password'), {}, { confirmPassword: PwdConfirmationMode.Lax }))
}
