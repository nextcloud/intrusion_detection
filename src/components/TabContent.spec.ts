/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, test } from 'vitest'
import { defineComponent, h } from 'vue'
import TabContent from './TabContent.vue'
import { sectionsOf, tabs, tabSections, visibleTabs } from '../extensions.ts'

const Own = defineComponent({ render: () => h('p', { 'data-test': 'own' }, 'own') })
const First = defineComponent({ render: () => h('p', { 'data-test': 'first' }, 'first') })
const Second = defineComponent({ render: () => h('p', { 'data-test': 'second' }, 'second') })

describe('sections within a tab', () => {
	const added: string[] = []

	afterEach(() => {
		for (const id of added.splice(0)) {
			tabSections.splice(tabSections.findIndex((s) => s.id === id), 1)
		}
	})

	test('a tab with sections but without a component is shown', () => {
		tabs.push({ id: 'test-sections-only', name: () => 'Test', icon: '', order: 1 })
		tabSections.push({ id: 'test-only', tab: 'test-sections-only', order: 10, component: First })
		added.push('test-only')
		try {
			expect(visibleTabs().map((tab) => tab.id)).toContain('test-sections-only')
		} finally {
			tabs.splice(tabs.findIndex((tab) => tab.id === 'test-sections-only'), 1)
		}
		tabs.push({ id: 'test-empty', name: () => 'Empty', icon: '', order: 2 })
		try {
			expect(visibleTabs().map((tab) => tab.id)).not.toContain('test-empty')
		} finally {
			tabs.splice(tabs.findIndex((tab) => tab.id === 'test-empty'), 1)
		}
		expect(sectionsOf('notifications').map((s) => s.id)).toEqual(['digest', 'webhook-events'])
	})

	test('sections follow the tab component, in order', () => {
		tabSections.push({ id: 'test-second', tab: 'test', order: 20, component: Second }, { id: 'test-first', tab: 'test', order: 10, component: First })
		added.push('test-second', 'test-first')
		const wrapper = mount(TabContent, { props: { tab: { id: 'test', name: () => 'Test', icon: '', order: 1, component: Own } } })
		expect(wrapper.findAll('p').map((p) => p.attributes('data-test'))).toEqual(['own', 'first', 'second'])
	})

	test('a tab without sections renders only its component', () => {
		const wrapper = mount(TabContent, { props: { tab: { id: 'nothing-here', name: () => 'Test', icon: '', order: 1, component: Own } } })
		expect(wrapper.findAll('p').map((p) => p.attributes('data-test'))).toEqual(['own'])
		expect(tabs.length).toBeGreaterThan(0)
	})
})
