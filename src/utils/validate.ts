/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type { Param, ParamValue } from '../types.ts'

import { t } from '@nextcloud/l10n'
import { APP_ID, formatDuration, formatValue } from './format.ts'

export interface Validation {
	/** The value in its canonical type, when valid */
	value?: ParamValue
	/** What is wrong, in plain words, when not */
	error?: string
}

/**
 * Validate a value typed into a settings field, with the same rules as the
 * server's `ParamDefinition::validate()`, so mistakes show before saving.
 * The server validates again; its answer is the one that counts.
 *
 * @param param - The setting
 * @param raw - The value from the field
 */
export function validateParam(param: Pick<Param, 'type' | 'min' | 'max' | 'choices'>, raw: unknown): Validation {
	switch (param.type) {
		case 'int':
		case 'duration':
			return validateInteger(param, raw)
		case 'float':
			return validateFloat(param, raw)
		case 'bool':
			return typeof raw === 'boolean' ? { value: raw } : { error: t(APP_ID, 'Choose on or off.') }
		case 'choice':
			return typeof raw === 'string' && param.choices.includes(raw)
				? { value: raw }
				: { error: t(APP_ID, 'Choose one of: {choices}.', { choices: param.choices.join(', ') }) }
		case 'string_list':
			return validateList(raw, () => true)
		case 'cidr_list':
			return validateList(raw, isCidr)
	}
	return { error: t(APP_ID, 'The value is not valid.') }
}

/**
 * @param param - The setting
 * @param raw - The value
 */
function validateInteger(param: Pick<Param, 'type' | 'min' | 'max'>, raw: unknown): Validation {
	const text = typeof raw === 'number' ? String(raw) : String(raw ?? '').trim()
	if (!/^-?\d{1,18}$/.test(text)) {
		return { error: t(APP_ID, 'Enter a whole number.') }
	}
	return checkBounds(param, Number(text))
}

/**
 * @param param - The setting
 * @param raw - The value
 */
function validateFloat(param: Pick<Param, 'type' | 'min' | 'max'>, raw: unknown): Validation {
	const text = typeof raw === 'number' ? String(raw) : String(raw ?? '').trim().replace(',', '.')
	const value = Number(text)
	if (text === '' || !Number.isFinite(value)) {
		return { error: t(APP_ID, 'Enter a number.') }
	}
	return checkBounds(param, value)
}

/**
 * @param param - The setting
 * @param value - The number
 */
function checkBounds(param: Pick<Param, 'type' | 'min' | 'max'>, value: number): Validation {
	const show = (bound: number) => param.type === 'duration' ? formatDuration(bound) : formatValue(bound, param.type)
	if (param.min !== null && value < param.min) {
		return { error: t(APP_ID, 'Enter at least {min}.', { min: show(param.min) }) }
	}
	if (param.max !== null && value > param.max) {
		return { error: t(APP_ID, 'Enter at most {max}.', { max: show(param.max) }) }
	}
	return { value }
}

/**
 * Lists are edited one entry per line.
 *
 * @param raw - The value: text with one entry per line, or a list
 * @param isValid - Validation of one entry
 */
function validateList(raw: unknown, isValid: (item: string) => boolean): Validation {
	const items = Array.isArray(raw) ? raw.map(String) : String(raw ?? '').split(/\r?\n|,/)
	const clean = [...new Set(items.map((item) => item.trim()).filter((item) => item !== ''))]
	for (const item of clean) {
		// eslint-disable-next-line no-control-regex
		if (item.length > 255 || /[\u0000-\u001F\u007F]/.test(item) || !isValid(item)) {
			return { error: t(APP_ID, 'This entry is not valid: {item}', { item: item.slice(0, 40) }) }
		}
	}
	return { value: clean }
}

/**
 * An IPv4 or IPv6 address, optionally with a prefix length.
 *
 * @param item - The entry
 */
export function isCidr(item: string): boolean {
	const [address = '', prefix, extra] = item.split('/')
	if (extra !== undefined || (prefix !== undefined && !/^\d{1,3}$/.test(prefix))) {
		return false
	}
	if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
		return address.split('.').every((part) => Number(part) <= 255) && (prefix === undefined || Number(prefix) <= 32)
	}
	return /^[0-9a-f:.]+$/i.test(address) && address.includes(':') && (prefix === undefined || Number(prefix) <= 128)
}
