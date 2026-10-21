<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamPreset;
use OCA\IntrusionDetection\Check\ParamText;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Check\Payload\CustomSignatures;
use OCA\IntrusionDetection\Check\Payload\FormMatch;
use OCA\IntrusionDetection\Check\Payload\PayloadHit;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCP\IL10N;

/**
 * SQL injection strings in web addresses and form fields, and attack code
 * hidden in base64 (section 10.19 of the concept).
 *
 * Nextcloud uses prepared statements, so such probes should not succeed, but
 * they reveal an attacker before the attacker finds something that does
 * work. The detector is {@see \OCA\IntrusionDetection\Guard\PayloadGuard};
 * the matching lives in {@see \OCA\IntrusionDetection\Check\Payload}.
 */
final class InjectionProbe implements ICheck, IExplainsDetection {
	public const ID = 'injection_probe';

	public const PARAM_AUTHENTICATED_MODE = 'authenticated_mode';
	public const PARAM_MIN_WEIGHT = 'sql_min_weight';
	public const PARAM_MAX_BYTES = 'max_bytes';
	public const PARAM_EXCLUDED = 'excluded_params';
	public const PARAM_DISABLED = 'disabled_signatures';
	public const PARAM_CUSTOM = 'custom_signatures';

	/** Free-text parameters that are never inspected by default */
	public const DEFAULT_EXCLUDED = [
		'term', 'search', 'query', 'filter', 'message', 'comment', 'content', 'text', 'description', 'title', 'name',
		'path', 'dir', 'file', 'files', 'filename',
	];

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::AddressesAndRequests,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				new ParamDefinition(self::PARAM_AUTHENTICATED_MODE, ParamType::Choice, Mode::Observe->value, choices: [Mode::Off->value, Mode::Observe->value, Mode::Protect->value]),
				new ParamDefinition(self::PARAM_MIN_WEIGHT, ParamType::Int, 3, min: 2, max: 20, preset: ParamPreset::Limit),
				new ParamDefinition(self::PARAM_MAX_BYTES, ParamType::Int, 8192, min: 1024, max: 65536),
				new ParamDefinition(self::PARAM_EXCLUDED, ParamType::StringList, self::DEFAULT_EXCLUDED, itemPattern: '/^[A-Za-z0-9_.\-]{1,64}$/', maxItems: 200, maxItemLength: 64),
				new ParamDefinition(self::PARAM_DISABLED, ParamType::StringList, [], itemPattern: '/^[a-z0-9_]{1,64}$/', maxItems: 100, maxItemLength: 64),
				new ParamDefinition(
					self::PARAM_CUSTOM,
					ParamType::StringList,
					[],
					maxItems: CustomSignatures::MAX_ITEMS,
					maxItemLength: CustomSignatures::MAX_LENGTH,
					itemValidator: static fn (string $entry, bool $thorough): ?string => (new CustomSignatures())->problem($entry, $thorough),
				),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::EveryRequestScan,
			stores: [DataKind::Detections, DataKind::RequestExcerpts, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('SQL injection and encoded payloads'),
				shortName: $l->t('Injection attempt'),
				summary: $l->t('Database commands in web addresses, and attack code hidden in base64.'),
				detects: $l->t('Attack tools try to break into web applications by putting database commands into web addresses, like ?id=1\' OR \'1\'=\'1 or UNION SELECT password FROM users. Some hide them in base64 so that simple filters miss them. Nextcloud itself is built to resist this, but such requests reveal an attacker before they find a weakness elsewhere, for example in an app.'),
				decides: $l->t('Looks at the web address and form fields of requests, up to {max_bytes} bytes each. A request fires when it matches signatures with a total weight of at least {sql_min_weight}: one stray quote never does, UNION SELECT alone does. Values that look like base64 are decoded and checked the same way, plus checks for script, PHP and shell code. File names, search fields and password fields are never inspected. Visitors who are not logged in are handled by the mode of this check; requests of logged-in users by the mode for logged-in users, now: {authenticated_mode}.'),
				wrong: $l->t('A third-party app that legitimately passes SQL-like text in a URL parameter. Add that parameter to the excluded list, or turn single signatures off. Use "Test a URL" to see exactly what matches. A link or an image on another website or in an email can make a visitor\'s browser send such a request: it is recorded, but the address is not blocked.'),
				data: $l->t('The parameter name, the matched signatures, and up to 200 characters of the suspicious value.'),
				params: [
					'authenticated_mode' => new ParamText($l->t('Logged-in users'), $l->t('What the check does with requests of logged-in users. It never goes beyond the mode of the check.')),
					'sql_min_weight' => new ParamText($l->t('Weight that fires'), $l->t('The matched signatures of one value must add up to at least this.')),
					'max_bytes' => new ParamText($l->t('Inspected per request'), $l->t('Input beyond this is ignored, so a huge request cannot slow the server down.'), $l->t('bytes')),
					'excluded_params' => new ParamText($l->t('Parameters never inspected'), $l->t('Free-text fields that may legitimately contain SQL-like text.')),
					'disabled_signatures' => new ParamText($l->t('Signatures turned off')),
					'custom_signatures' => new ParamText($l->t('Your own signatures')),
				],
			),
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$explanation = $detection->getExplanationData();
		$facts = is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [];
		$param = (string)($facts['param'] ?? '');
		$where = match ($facts['location'] ?? '') {
			PayloadHit::LOCATION_PATH => $l->t('the path of the web address'),
			PayloadHit::LOCATION_FORM => $l->t('the form field "%s"', [$param]),
			default => $l->t('the parameter "%s" of the web address', [$param]),
		};
		$weights = is_array($facts['weights'] ?? null) ? $facts['weights'] : [];
		$listed = [];
		foreach ($weights as $id => $weight) {
			$listed[] = sprintf('%s (%d)', (string)$id, (int)$weight);
		}

		$sentences = [];
		$sentences[] = $l->t('The address %1$s sent a request in which %2$s matched these signatures: %3$s. Their total weight was %4$s; the limit was %5$s.', [
			(string)($detection->getIp() ?? '?'),
			$where,
			$listed === [] ? $l->t('none') : implode(', ', $listed),
			(string)(int)($facts['weight'] ?? 0),
			(string)(int)($facts['minWeight'] ?? 0),
		]);
		$sentences[] = match ($facts['encoding'] ?? FormMatch::ENCODING_NONE) {
			FormMatch::ENCODING_BASE64 => $l->t('The value was hidden in base64; it matched after decoding.'),
			FormMatch::ENCODING_BASE64_TWICE => $l->t('The value was hidden in base64 twice; it matched after decoding it two times.'),
			default => $l->t('The value matched as it was sent, after URL decoding.'),
		};
		$excerpt = (string)($facts['excerpt'] ?? '');
		if ($excerpt !== '') {
			$sentences[] = $l->t('The suspicious part read: %s', ['“' . $excerpt . '”']);
		}
		$others = is_array($facts['otherParams'] ?? null) ? array_map('strval', $facts['otherParams']) : [];
		if ($others !== []) {
			$sentences[] = $l->t('These parameters matched as well: %s.', [implode(', ', $others)]);
		}
		if (($facts['authenticated'] ?? false) === true) {
			$sentences[] = $l->t('The request came from the logged-in account %s. Check whether this account is being used to probe the server.', [(string)$detection->getUid()]);
		} else {
			$sentences[] = $l->t('The request was not logged in.');
		}
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('Requests like this came %n time within the hour.', 'Requests like this came %n times within the hour.', $detection->getHits());
		}
		return $sentences;
	}
}
