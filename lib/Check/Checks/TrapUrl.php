<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Traps\TrapPaths;
use OCP\IL10N;

/**
 * A request for a path no legitimate Nextcloud client ever requests, from a
 * client that is not logged in. The guard is
 * {@see \OCA\IntrusionDetection\Guard\TrapUrlGuard}.
 */
final class TrapUrl implements ICheck, IExplainsDetection, ISimulatable, IValidatesParams {
	public const ID = 'trap_url';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Traps,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [
				new ParamDefinition('builtin_enabled', ParamType::Bool, true),
				new ParamDefinition('autodiscover', ParamType::Bool, false),
				new ParamDefinition('paths', ParamType::StringList, [], itemPattern: TrapPaths::CUSTOM_PATTERN, maxItems: TrapPaths::MAX_CUSTOM, maxItemLength: 200),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::EveryRequestTiny,
			stores: [DataKind::Detections, DataKind::Bans],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Trap URLs'),
				shortName: $l->t('Trap URL'),
				summary: $l->t('A visitor who is not logged in requests a path that no Nextcloud client ever requests.'),
				detects: $l->t('Scanners look for weaknesses of other software, such as WordPress logins, leaked configuration files or database tools. Nextcloud has none of these, so anyone who asks for them is scanning your server.'),
				decides: $l->t('Fires when a visitor who is not logged in requests one of the built-in trap paths (switched {builtin_enabled}), the Exchange autodiscover path (switched {autodiscover}), or one of your own paths: {paths}. Your own paths match exactly, or as a prefix when they end with "*".'),
				wrong: $l->t('Logged-in users and clients never trip it; a request with a made-up cookie or password is checked once its login failed. A browser extension or a monitoring tool that probes such paths could trip it; put its address on the brute-force allowlist. Some paths never reach Nextcloud without the web server rule from the Blocks tab: nginx answers hidden paths such as /.env itself, and Apache with PHP-FPM answers .php paths such as /wp-login.php. A link or an image on another website or in an email can make a visitor\'s browser request such a path: those requests are recorded, but the address is not blocked.'),
				data: $l->t('Detections: the address, the requested path (at most 200 characters), and the time.'),
				params: [
					'builtin_enabled' => new ParamText($l->t('Built-in trap paths'), $l->t('Paths of other software that scanners look for.')),
					'autodiscover' => new ParamText($l->t('Exchange autodiscover path'), $l->t('Some mail programs request it on any server; only switch it on if nobody uses one with your domain.')),
					'paths' => new ParamText($l->t('Your own paths'), $l->t('Exact, or a prefix when they end with *.')),
				],
			),
			simulatable: true,
			honoursLure: true,
			trustedLoginsExempt: false,
		);
	}

	#[\Override]
	public function validateParam(string $name, int|float|bool|string|array $value): int|float|bool|string|array {
		if ($name !== 'paths' || !is_array($value)) {
			return $value;
		}
		$paths = [];
		foreach ($value as $path) {
			$path = strtolower($path);
			if (TrapPaths::conflictsWithNextcloud($path)) {
				throw new InvalidParamException('nextcloud_path', ['param' => $name, 'item' => $path]);
			}
			$paths[] = $path;
		}
		return array_values(array_unique($paths));
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [$l->t('The address %1$s requested %2$s without being logged in. No Nextcloud client ever requests this path.', [
			(string)$detection->getIp(),
			$facts->string('path'),
		])];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It requested trap paths %n time between %1$s and %2$s.', 'It requested trap paths %n times between %1$s and %2$s.', $detection->getHits(), [
				$this->dates->dateTime($detection->getCreatedAt()),
				$this->dates->time($detection->getLastSeenAt()),
			]);
		}
		return $sentences;
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: ['path' => '/wp-login.php', 'trap' => '/wp-login.php', 'simulated' => true],
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
