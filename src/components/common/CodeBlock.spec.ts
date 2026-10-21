/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import CodeBlock from './CodeBlock.vue'

const JAIL = '[nextcloud-ids]\nenabled  = true\nfilter   = nextcloud-ids\n'

describe('CodeBlock', () => {
	let writeText: ReturnType<typeof vi.fn>

	beforeEach(() => {
		writeText = vi.fn(() => Promise.resolve())
		Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
	})

	test('shows the file and the snippet exactly as given', () => {
		const wrapper = mount(CodeBlock, { props: { content: JAIL, file: '/etc/fail2ban/jail.d/nextcloud-ids.local', label: 'fail2ban jail' } })
		expect(wrapper.text()).toContain('/etc/fail2ban/jail.d/nextcloud-ids.local')
		expect(wrapper.get('pre').element.textContent).toBe(JAIL)
		expect(wrapper.get('pre').attributes('tabindex')).toBe('0')
	})

	test('copies the whole snippet and says so', async () => {
		const wrapper = mount(CodeBlock, { props: { content: JAIL, file: '/etc/x', label: 'fail2ban jail' } })
		const copy = wrapper.get('[data-test="copy"]')
		expect(copy.attributes('aria-label')).toBe('Copy fail2ban jail')
		await copy.trigger('click')
		await flushPromises()
		expect(writeText).toHaveBeenCalledWith(JAIL)
		expect(copy.text()).toBe('Copied')
	})
})
