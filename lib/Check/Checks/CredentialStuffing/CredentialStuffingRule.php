<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\CredentialStuffing;

/**
 * Why a credential stuffing detection fired, as stored in its facts.
 */
enum CredentialStuffingRule: string {
	/** One address failed for many accounts */
	case Source = 'source';
	/** The addresses of one IPv4 /24 together */
	case Network = 'network';
	/** The whole server, from many addresses */
	case Distributed = 'distributed';
}
