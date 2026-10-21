/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { defineComponent, h } from 'vue'
import PersonalSettings from './PersonalSettings.vue'
import { PERSONAL_ORDER, personalSections } from '../personal/extensions.ts'
import { personal } from '../personal/store.ts'
import { overview } from '../tests/personalFixtures.ts'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

vi.mock('../personal/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchEvents: vi.fn(() => Promise.resolve([])),
	fetchLogins: vi.fn(() => Promise.resolve([])),
	fetchKnownDevices: vi.fn(() => Promise.resolve([])),
	fetchTrustedNetworks: vi.fn(() => Promise.resolve([])),
}))

vi.mock('../services/secureAccount.ts', () => ({
	fetchSecureAccount: vi.fn(() => Promise.resolve({ progress: { active: false } })),
	fetchSecurityChanges: vi.fn(() => Promise.resolve([])),
}))

const original = [...personalSections]

/**
 * Mount the page once its sections are loaded.
 */
async function mountPage() {
	const wrapper = mount(PersonalSettings)
	for (let i = 0; i < 5; i++) {
		await flushPromises()
		await vi.dynamicImportSettled()
	}
	return wrapper
}

enableAutoUnmount(afterEach)

describe('PersonalSettings', () => {
	beforeEach(() => {
		personal.overview = overview()
		personal.knownDevicesEnabled = true
	})

	afterEach(() => {
		personalSections.splice(0, personalSections.length, ...original)
	})

	test('renders every section in its order under one heading', async () => {
		const wrapper = await mountPage()
		expect(wrapper.find('h2').text()).toBe('Security events')
		expect(wrapper.findAll('[data-section]').map((s) => s.attributes('data-section'))).toEqual([
			'secure-account',
			'status',
			'email-hint',
			'events',
			'failed-logins',
			'logins',
			'security-changes',
			'known-devices',
			'trusted-networks',
			'log-out-elsewhere',
		])
		expect(wrapper.get('[data-test="status"]').text()).toContain('No unusual activity in the last 30 days')
		expect(wrapper.find('[data-test="email-hint"]').exists()).toBe(false)
	})

	test('the checklist and the security changes sit in their reserved places', async () => {
		const wrapper = await mountPage()
		const ids = wrapper.findAll('[data-section]').map((s) => s.attributes('data-section'))
		expect(ids[0]).toBe('secure-account')
		expect(ids.indexOf('security-changes')).toBe(ids.indexOf('logins') + 1)
		expect(wrapper.get('[data-section="secure-account"]').text(), 'No checklist is open').toBe('')
	})

	test('a later part plugs into the list without changing the page', async () => {
		personalSections.push({ id: 'test-part', order: PERSONAL_ORDER.logOutElsewhere + 1, component: defineComponent({ render: () => h('p', 'Part') }) })
		const wrapper = await mountPage()
		const ids = wrapper.findAll('[data-section]').map((s) => s.attributes('data-section'))
		expect(ids[ids.length - 1]).toBe('test-part')
		expect(wrapper.get('[data-section="test-part"]').text()).toBe('Part')
	})

	test('remembered devices and trusted networks share a row', async () => {
		const wrapper = await mountPage()
		const half = wrapper.findAll('[data-section]').filter((s) => s.classes().some((c) => c.includes('half')))
		expect(half.map((s) => s.attributes('data-section'))).toEqual(['known-devices', 'trusted-networks'])
	})
})
