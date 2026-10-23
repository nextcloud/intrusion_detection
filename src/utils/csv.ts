/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * One quoted CSV cell. A value that a spreadsheet would read as a formula
 * gets a leading `'`.
 *
 * @param value - The cell value
 */
export function csvCell(value: string): string {
	const safe = /^[=+\-@\t\r\0]/.test(value) ? `'${value}` : value
	return `"${safe.replaceAll('"', '""')}"`
}
