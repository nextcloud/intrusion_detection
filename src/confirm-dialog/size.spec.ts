/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import { execFileSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { expect, test } from 'vitest'

test('the confirm-dialog script stays under 2 KB, minified as it is shipped on every page', () => {
	// In its own process: esbuild does not run inside the test's browser environment.
	const esbuild = createRequire(import.meta.url).resolve('esbuild/bin/esbuild')
	const bundle = execFileSync(esbuild, [resolve(import.meta.dirname, '..', 'confirm-dialog.ts'), '--bundle', '--minify', '--format=esm', '--target=es2020'])
	expect(bundle.byteLength).toBeGreaterThan(500)
	expect(bundle.byteLength).toBeLessThan(2048)
})
