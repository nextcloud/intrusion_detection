/*!
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** The shapes of the secure-account API, generated from `openapi-full.json`. */

import type { components } from './types/openapi/openapi-full.ts'

type Schemas = components['schemas']

export type SecurityChange = Schemas['SecurityChange']
export type SecureAccountStep = Schemas['SecureAccountStep']
export type SecureAccountProgress = Schemas['SecureAccountProgress']
export type SecureAccountSession = Schemas['SecureAccountSession']
export type SecureAccountShare = Schemas['SecureAccountShare']
export type SecureAccount = Schemas['SecureAccount']
export type AccountGuide = Schemas['AccountGuide']

export type SecureAccountStepId = Schemas['SecureAccountStep']['id']
