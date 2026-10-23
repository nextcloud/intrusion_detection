/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { AdminGrantRequest } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import AdminGrantRequests from './AdminGrantRequests.vue'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

/**
 * @param request - What differs from a request to make bob an administrator
 */
function request(request: Partial<AdminGrantRequest>): AdminGrantRequest {
	return {
		id: 1,
		kind: 'admin_grant',
		change: null,
		uid: 'bob',
		displayName: 'Bob',
		group: 'admin',
		requestedBy: 'alice',
		requesterName: 'Alice',
		createdAt: 1800000000,
		expiresAt: 1800600000,
		canApprove: true,
		...request,
	}
}

describe('the requests that wait for a second administrator', () => {
	test('a new administrator names the account and the group', () => {
		const text = mount(AdminGrantRequests, { props: { requests: [request({})] } }).text()
		expect(text).toContain('Alice asks to make Bob an administrator')
		expect(text).toContain('Group admin')
	})

	test('a settings change says what it does', () => {
		const text = mount(AdminGrantRequests, {
			props: { requests: [request({ kind: 'settings', change: 'Switch intrusion detection off.', uid: 'alice', displayName: 'Alice', group: '' })] },
		}).text()
		expect(text).toContain('Alice asks for a change: Switch intrusion detection off.')
		expect(text).not.toContain('Group')
	})
})
