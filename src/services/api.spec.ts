/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import axios from '@nextcloud/axios'
import { PwdConfirmationMode } from '@nextcloud/password-confirmation'
import { describe, expect, test, vi } from 'vitest'
import { ApiError, approveRequest, fetchStatus, isRateLimited, rejectRequest, updateCheck } from './api.ts'

vi.mock('@nextcloud/axios', async (importOriginal) => ({
	...(await importOriginal<object>()),
	default: { request: vi.fn(() => Promise.resolve({ data: { ocs: { meta: {}, data: {} } } })) },
}))

/**
 * @param status - The HTTP status of the answer
 */
function httpError(status: number): Error {
	return Object.assign(new Error('Request failed'), { isAxiosError: true, response: { status, data: '' } })
}

describe('a refusal for too many requests', () => {
	test('is told apart from other failures, also when the server explained it', () => {
		expect(isRateLimited(httpError(429))).toBe(true)
		expect(isRateLimited(new ApiError('Slow down', null, { cause: httpError(429) }))).toBe(true)
		expect(isRateLimited(httpError(500))).toBe(false)
		expect(isRateLimited(new ApiError('Not valid'))).toBe(false)
		expect(isRateLimited(new Error('down'))).toBe(false)
	})
})

describe('a request', () => {
	test('becomes an ApiError with the setting when the server explains the failure', async () => {
		const refusal = Object.assign(new Error('Request failed'), { isAxiosError: true, response: { status: 400, data: { ocs: { meta: { message: '' }, data: { message: 'Too high', param: 'min_failures' } } } } })
		vi.mocked(axios.request).mockRejectedValueOnce(refusal)
		const error = await updateCheck('credential_stuffing', { params: { min_failures: 5000 } }).catch((e: unknown) => e)
		expect(error).toBeInstanceOf(ApiError)
		expect(error).toMatchObject({ message: 'Too high', param: 'min_failures', cause: refusal })
	})

	test('passes the signal that cancels it', async () => {
		const controller = new AbortController()
		await fetchStatus(controller.signal)
		expect(vi.mocked(axios.request).mock.lastCall?.[0]).toMatchObject({ method: 'get', signal: controller.signal })
	})
})

describe('a decision on a request for approval', () => {
	test('approving asks for the password, rejecting does not', async () => {
		vi.mocked(axios.request).mockClear()
		await approveRequest(7)
		await rejectRequest(7)
		const [[approve], [reject]] = vi.mocked(axios.request).mock.calls as unknown as [[{ method: string, url: string, confirmPassword?: unknown }], [{ method: string, url: string, confirmPassword?: unknown }]]
		expect(approve).toMatchObject({ method: 'post', confirmPassword: PwdConfirmationMode.Lax })
		expect(approve.url).toMatch(/\/approvals\/7\/approve$/)
		expect(reject.method).toBe('post')
		expect(reject.url).toMatch(/\/approvals\/7\/reject$/)
		expect(reject.confirmPassword).toBeUndefined()
	})
})
