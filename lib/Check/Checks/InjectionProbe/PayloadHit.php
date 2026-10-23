<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * A request part that matched: what a detection stores about it. Never the
 * full request, and never anything from a parameter that is not inspected.
 */
final class PayloadHit {
	public const LOCATION_PATH = 'path';
	public const LOCATION_QUERY = 'query';
	public const LOCATION_FORM = 'form';

	/** At most this many further matching parameters are named */
	public const MAX_OTHERS = 10;

	/**
	 * @param self::LOCATION_* $location
	 * @param string $param the parameter name ('' for the path)
	 * @param array<string, int> $signatures signature id => weight
	 * @param FormMatch::ENCODING_* $encoding
	 * @param list<string> $otherParams further parameters that matched too
	 */
	public function __construct(
		public readonly string $location,
		public readonly string $param,
		public readonly array $signatures,
		public readonly int $weight,
		public readonly int $minWeight,
		public readonly string $encoding,
		public readonly string $excerpt,
		public readonly array $otherParams = [],
	) {
	}

	/**
	 * The facts a detection stores (section 16.4 of the concept).
	 *
	 * @param ?string $credential what the request carried if it claimed to be logged in, see PendingHit::CREDENTIAL_*
	 */
	public function facts(bool $authenticated, ?string $credential): InjectionProbeFacts {
		return new InjectionProbeFacts(
			location: $this->location,
			param: $this->param,
			signatures: array_map('strval', array_keys($this->signatures)),
			weights: $this->signatures,
			weight: $this->weight,
			minWeight: $this->minWeight,
			encoding: $this->encoding,
			excerpt: $this->excerpt,
			otherParams: $this->otherParams,
			signaturesVersion: Signatures::VERSION,
			authenticated: $authenticated,
			credential: $credential,
		);
	}
}
