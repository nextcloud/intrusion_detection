/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, describe, expect, test, vi } from 'vitest'
import LookupBox from './LookupBox.vue'
import { lookup } from '../../services/api.ts'
import { makeDetail } from '../../tests/fixtures.ts'

vi.mock('../../services/api.ts', async (importOriginal) => ({
	...(await importOriginal<object>()),
	lookup: vi.fn(),
}))

/**
 * Type a query and submit it.
 *
 * @param query - What to look up
 */
async function search(query: string) {
	const wrapper = mount(LookupBox)
	await wrapper.get('input').setValue(query)
	await wrapper.get('form').trigger('submit')
	await flushPromises()
	return wrapper
}

describe('LookupBox', () => {
	afterEach(() => {
		vi.mocked(lookup).mockReset()
	})

	test('a reference opens its block, with the detection that caused it', async () => {
		const detail = makeDetail()
		vi.mocked(lookup).mockResolvedValue({ kind: 'reference', query: 'k7q2mpxa', bans: detail.bans, detections: [detail.detection], user: null })
		const wrapper = await search('k7q2mpxa')
		expect(lookup).toHaveBeenCalledWith('k7q2mpxa')
		const result = wrapper.get('[data-test="lookup-result"]')
		expect(result.text()).toContain('Block K7Q2-MPXA')
		expect(result.text()).toContain('203.0.113.7')
		expect(result.text()).not.toContain('/32')
		expect(result.text()).toContain('Credential stuffing')

		await result.findAll('button').find((b) => b.text() === 'Lift block')!.trigger('click')
		expect(wrapper.emitted('lift')?.[0]?.[0]).toMatchObject({ id: 7 })

		await result.findAll('button').find((b) => b.text().includes('Credential stuffing'))!.trigger('click')
		expect(wrapper.emitted('openDetection')?.[0]).toEqual([42])
	})

	test('an address that is not blocked says so', async () => {
		vi.mocked(lookup).mockResolvedValue({ kind: 'address', query: '198.51.100.9', bans: [], detections: [], user: null })
		const wrapper = await search('198.51.100.9')
		expect(wrapper.text()).toContain('Address 198.51.100.9')
		expect(wrapper.text()).toContain('This address is not blocked right now.')
		expect(wrapper.text()).toContain('No detections in the last 30 days.')
	})

	test('an account lists the detections about it', async () => {
		const detail = makeDetail()
		vi.mocked(lookup).mockResolvedValue({ kind: 'user', query: 'alice', bans: [], detections: [detail.detection], user: { uid: 'alice', displayName: 'Alice Liddell' } })
		const wrapper = await search('alice')
		expect(wrapper.text()).toContain('Account alice (Alice Liddell)')
		expect(wrapper.text()).toContain('1 detection in the last 30 days')
	})

	test('nothing found explains what can be looked up', async () => {
		vi.mocked(lookup).mockResolvedValue({ kind: 'none', query: 'zzz', bans: [], detections: [], user: null })
		const wrapper = await search('zzz')
		expect(wrapper.text()).toContain('Nothing found for "zzz"')
		expect(wrapper.text()).toContain('Try a reference like K7Q2-MPXA')
	})

	test('an empty box does not search', async () => {
		const wrapper = await search('   ')
		expect(lookup).not.toHaveBeenCalled()
		expect(wrapper.find('[data-test="lookup-result"]').exists()).toBe(false)
	})
})
