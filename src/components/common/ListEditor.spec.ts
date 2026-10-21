/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { describe, expect, test } from 'vitest'
import ListEditor from './ListEditor.vue'

/**
 * @param props - Extra props
 */
function editor(props: Record<string, unknown> = {}) {
	return mount(ListEditor, {
		props: {
			items: ['root', 'support'],
			label: 'Reserve a name',
			normalise: (value: string) => value.trim().toLowerCase(),
			validate: (value: string) => value.includes(' ') ? 'No spaces, please.' : null,
			...props,
		},
	})
}

/**
 * @param wrapper - The editor
 */
function addButton(wrapper: ReturnType<typeof editor>) {
	return wrapper.get('[data-test="list-add"]')
}

describe('ListEditor', () => {
	test('a typed entry is checked inline, before anything is saved', async () => {
		const wrapper = editor()
		const input = wrapper.get('input')
		expect(addButton(wrapper).attributes('disabled')).toBeDefined()

		await input.setValue('two words')
		expect(wrapper.text()).toContain('No spaces, please.')
		expect(addButton(wrapper).attributes('disabled')).toBeDefined()

		await input.setValue(' ROOT ')
		expect(wrapper.text()).toContain('"root" is in the list already.')

		await input.setValue(' Admin ')
		expect(wrapper.text()).not.toContain('No spaces')
		expect(addButton(wrapper).attributes('disabled')).toBeUndefined()
		await wrapper.get('form').trigger('submit')
		expect(wrapper.emitted('add')).toEqual([[['admin']]])
	})

	test('the list size is limited', async () => {
		const wrapper = editor({ max: 2 })
		await wrapper.get('input').setValue('admin')
		expect(wrapper.text()).toContain('The list can have at most 2 entries.')
	})

	test('an error from the server is shown after the change', async () => {
		const wrapper = editor()
		await wrapper.get('input').setValue('alice')
		await wrapper.get('form').trigger('submit')
		await wrapper.setProps({ error: '"alice" is an existing account.' })
		expect(wrapper.text()).toContain('"alice" is an existing account.')
	})

	test('entries are removed one by one, and entries with a problem are marked', async () => {
		const wrapper = editor({ problems: { support: 'An account with this name exists now.' } })
		const chips = wrapper.findAll('li')
		expect(chips[1]!.attributes('title')).toBe('An account with this name exists now.')
		expect(chips[1]!.text()).toContain('An account with this name exists now.')
		await chips[0]!.get('button').trigger('click')
		expect(wrapper.emitted('remove')).toEqual([['root']])
	})

	test('suggestions are added with one click, or all at once', async () => {
		const wrapper = editor({ suggestions: ['admin', 'root', 'test'] })
		const suggestions = wrapper.findAll('button').filter((b) => b.attributes('aria-label')?.startsWith('Add '))
		expect(suggestions.map((b) => b.text())).toEqual(['admin', 'test'])
		await suggestions[0]!.trigger('click')
		await wrapper.findAll('button').find((b) => b.text() === 'Add all')!.trigger('click')
		expect(wrapper.emitted('add')).toEqual([[['admin']], [['admin', 'test']]])
	})
})
