/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { WebhookEvents } from '../../types.ts'

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import WebhookEventsSection from './WebhookEventsSection.vue'
import { fetchWebhookEvents, updateSettings } from '../../services/api.ts'
import { saveSettings, state } from '../../store.ts'

const mounted: { unmount: () => void }[] = []

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	fetchWebhookEvents: vi.fn(),
	updateSettings: vi.fn(),
}))

const detectionExample = {
	event: { type: 'detection', detectionId: 42, checkId: 'credential_stuffing', severity: 'medium', enforced: true, ip: '203.0.113.7', uid: null, actions: [{ type: 'ban', enforced: true, bans: [{ reference: 'K7Q2-MPXA', expiresAt: 1 }] }], time: 1, link: 'https://cloud.example.com/settings/admin/intrusion_detection#detection-42', class: 'OCA\\IntrusionDetection\\Event\\DetectionCreatedEvent' },
	user: null,
	time: 1,
}

/**
 * @param overrides - Fields to change
 */
function events(overrides: Partial<WebhookEvents> = {}): WebhookEvents {
	return {
		includeIp: true,
		webhooksEnabled: true,
		events: [
			{ class: 'OCA\\IntrusionDetection\\Event\\DetectionCreatedEvent', name: 'A check found something', description: 'Sent for every new detection.', example: detectionExample },
			{ class: 'OCA\\IntrusionDetection\\Event\\BanCreatedEvent', name: 'An address was blocked', description: 'Sent when an address is blocked.', example: { event: { type: 'ban_created' }, user: null, time: 1 } },
		],
		...overrides,
	}
}

/**
 * @param value - What the API returns
 */
async function mountSection(value = events()) {
	vi.mocked(fetchWebhookEvents).mockResolvedValue(value)
	const wrapper = mount(WebhookEventsSection, { attachTo: document.body })
	mounted.push(wrapper)
	await flushPromises()
	return wrapper
}

describe('WebhookEventsSection', () => {
	beforeEach(() => {
		state.settings = [
			{ name: 'events_include_ip', type: 'bool', default: true, min: null, max: null, choices: [], value: true, label: 'Addresses in webhook events', help: '', unit: '', group: 'notifications' },
		]
	})

	afterEach(() => {
		mounted.splice(0).forEach((wrapper) => wrapper.unmount())
		vi.mocked(fetchWebhookEvents).mockReset()
		document.body.innerHTML = ''
	})

	test('lists every event with its name, and its pretty-printed example payload behind a toggle', async () => {
		const wrapper = await mountSection()
		const items = wrapper.findAll('[data-test="webhook-event"]')
		expect(items).toHaveLength(2)
		expect(items[0]!.text()).toContain('A check found something')
		expect(items[0]!.text()).toContain('OCA\\IntrusionDetection\\Event\\DetectionCreatedEvent')
		expect(wrapper.find('[data-test="webhook-payload"]').exists()).toBe(false)
		const toggle = items[0]!.get('[data-test="webhook-payload-toggle"] button')
		expect(toggle.attributes('aria-expanded')).toBe('false')
		await toggle.trigger('click')
		expect(toggle.attributes('aria-expanded')).toBe('true')
		expect(wrapper.findAll('[data-test="webhook-payload"]')).toHaveLength(1)
		const payload = wrapper.get('[data-test="webhook-payload"] pre').text()
		expect(payload).toBe(JSON.stringify(detectionExample, null, 2))
		expect(payload).toContain('\n  "event": {\n')
		expect(wrapper.text()).toContain('Addresses in webhook events')
	})

	test('says when the Webhooks app is not enabled', async () => {
		const wrapper = await mountSection(events({ webhooksEnabled: false }))
		expect(wrapper.find('[data-test="webhooks-disabled"]').exists()).toBe(true)
	})

	test('copies an event name', async () => {
		const writeText = vi.fn(() => Promise.resolve())
		Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
		const wrapper = await mountSection()
		await wrapper.get('button[aria-label^="Copy event name"]').trigger('click')
		expect(writeText).toHaveBeenCalledWith('OCA\\IntrusionDetection\\Event\\DetectionCreatedEvent')
	})

	test('the examples are loaded again when the address setting was saved', async () => {
		await mountSection()
		vi.mocked(updateSettings).mockResolvedValue({ settings: state.settings.map((s) => ({ ...s, value: false })), templates: {} })
		await saveSettings({ events_include_ip: false })
		expect(fetchWebhookEvents).toHaveBeenCalledTimes(2)
	})
})
