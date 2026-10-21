/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { beforeEach, describe, expect, test, vi } from 'vitest'
import { showNotice } from './login-notice.ts'

vi.mock('@nextcloud/initial-state', () => ({ loadState: vi.fn(() => '') }))

describe('the login page notice during lockdown', () => {
	beforeEach(() => {
		document.body.innerHTML = '<div class="guest-content"><div><div id="login"></div></div></div>'
	})

	test('it is shown above the login box, as text', () => {
		const notice = showNotice('Extra security checks are active. <b>You</b> may be asked to confirm your login.')!
		expect(notice.getAttribute('role')).toBe('note')
		expect(document.querySelector('.guest-content')!.firstElementChild).toBe(notice)
		expect(notice.textContent).toContain('<b>You</b> may be asked')
		expect(notice.querySelector('b')).toBeNull()
	})

	test('once only, and nothing without a text or a login page', () => {
		showNotice('Notice')
		expect(showNotice('Notice')).toBeNull()
		expect(document.querySelectorAll('.ids-login-notice')).toHaveLength(1)
		expect(showNotice('')).toBeNull()
		document.body.innerHTML = ''
		expect(showNotice('Notice')).toBeNull()
	})
})
