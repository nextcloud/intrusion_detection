/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { CheckRef, TrapPathList, TrapWebServer } from '../../types.ts'

import { mount } from '@vue/test-utils'
import { describe, expect, test, vi } from 'vitest'
import TrapPathsCard from './TrapPathsCard.vue'

vi.mock('@nextcloud/dialogs', () => ({ showError: vi.fn(), showSuccess: vi.fn() }))

const check: CheckRef = { id: 'trap_url', name: 'Trap URLs', mode: { configured: 'protect', effective: 'protect', reason: null, missing: null, default: 'protect' } }

/**
 * @param webServer - The web server that served the page
 * @param needRule - The paths it answers itself
 */
function paths(webServer: TrapWebServer, needRule: string[]): TrapPathList {
	return {
		builtinEnabled: true,
		builtin: [
			{ path: '/wp-login.php', text: 'WordPress', answeredBy: ['apache_fpm'] },
			{ path: '/.env', text: 'Configuration files', answeredBy: ['nginx'] },
			{ path: '/phpmyadmin', text: 'phpMyAdmin', answeredBy: [] },
		],
		autodiscover: false,
		autodiscoverPath: '/autodiscover/autodiscover.xml',
		custom: [],
		webServer,
		needRule,
		max: 100,
		snippets: [
			{ id: 'nginx', file: '/etc/nginx/sites-available/nextcloud', content: 'location' },
			{ id: 'apache', file: '/etc/apache2/sites-available/nextcloud.conf', content: 'RewriteRule' },
		],
		snippetsSkipped: [],
	}
}

/**
 * @param list - The trap paths
 */
function card(list: TrapPathList) {
	return mount(TrapPathsCard, { props: { paths: list, check } })
}

describe('TrapPathsCard', () => {
	test('names the paths this server answers itself', () => {
		const wrapper = card(paths('nginx', ['/.env', '/.git/']))
		expect(wrapper.find('[data-test="trap-this-server"]').text()).toBe('On this server (nginx), 2 trap paths reach Nextcloud only with the rule: /.env /.git/')
	})

	test('says when every path reaches Nextcloud already', () => {
		const wrapper = card(paths('apache', []))
		expect(wrapper.find('[data-test="trap-this-server"]').text()).toBe('On this server (Apache), your trap paths reach Nextcloud without the rule.')
	})

	test('says nothing about an unknown server', () => {
		expect(card(paths('unknown', [])).find('[data-test="trap-this-server"]').exists()).toBe(false)
	})

	test('marks the built-in paths that need the rule', async () => {
		const wrapper = card(paths('unknown', []))
		await wrapper.find('button[aria-expanded]').trigger('click')
		const text = wrapper.text()
		expect(text).toContain('Needs the web server rule on Apache with PHP-FPM.')
		expect(text).toContain('Needs the web server rule on nginx.')
		expect(text.match(/Needs the web server rule/g)).toHaveLength(2)
	})
})
