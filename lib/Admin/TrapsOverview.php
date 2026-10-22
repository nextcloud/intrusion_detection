<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Decoy\Db\Decoy;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCA\IntrusionDetection\Traps\TrapPaths;
use OCA\IntrusionDetection\Traps\TrapPathSnippets;
use OCP\IL10N;

/**
 * The Decoys tab: decoy credentials, reserved names and trap paths. Decoys
 * are presented without the fingerprint of their secret; the secret itself
 * exists only in the answer that created the decoy.
 *
 * @psalm-import-type IntrusionDetectionTraps from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDecoy from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionReservedNames from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionTrapPaths from ResponseDefinitions
 */
class TrapsOverview {
	public function __construct(
		private readonly DecoyService $decoys,
		private readonly ReservedNames $reservedNames,
		private readonly TrapNameCollisions $collisions,
		private readonly TrapPathSnippets $snippets,
		private readonly CheckSettings $settings,
		private readonly CheckSummary $checks,
	) {
	}

	/**
	 * @return IntrusionDetectionTraps
	 */
	public function get(IL10N $l): array {
		return [
			'decoys' => array_map(self::decoy(...), $this->decoys->list()),
			'decoyCheck' => $this->checks->of(DecoyCredential::ID, $l),
			'reservedCheck' => $this->checks->of(ReservedName::ID, $l),
			'trapCheck' => $this->checks->of(TrapUrl::ID, $l),
			'decoyCollisions' => $this->decoys->loginNameCollisions(),
			'reservedNames' => $this->reservedNames(),
			'trapPaths' => $this->trapPaths($l),
		];
	}

	/**
	 * @return IntrusionDetectionDecoy
	 */
	public static function decoy(Decoy $decoy): array {
		return [
			'id' => $decoy->getId(),
			'label' => $decoy->getLabel(),
			'loginName' => $decoy->getLoginName(),
			'format' => $decoy->getFormat(),
			'createdBy' => $decoy->getCreatedBy(),
			'createdAt' => $decoy->getCreatedAt(),
			'lastTriggeredAt' => $decoy->getLastTriggeredAt(),
			'triggerCount' => $decoy->getTriggerCount(),
		];
	}

	/**
	 * @return IntrusionDetectionReservedNames
	 */
	public function reservedNames(): array {
		return [
			'names' => $this->reservedNames->list(),
			'suggestions' => $this->reservedNames->suggestions(),
			'collisions' => $this->collisions->reserved(),
			'max' => ReservedNames::MAX_NAMES,
		];
	}

	/**
	 * @return IntrusionDetectionTrapPaths
	 */
	public function trapPaths(IL10N $l): array {
		$snippets = $this->snippets->all();
		$builtinEnabled = $this->settings->paramBool(TrapUrl::ID, 'builtin_enabled');
		$autodiscover = $this->settings->paramBool(TrapUrl::ID, 'autodiscover');
		$custom = $this->settings->paramList(TrapUrl::ID, 'paths');
		$webServer = TrapPaths::webServer(
			is_string($_SERVER['SERVER_SOFTWARE'] ?? null) ? $_SERVER['SERVER_SOFTWARE'] : '',
			PHP_SAPI,
			getenv('front_controller_active') === 'true',
		);
		return [
			'builtinEnabled' => $builtinEnabled,
			'builtin' => array_map(static fn (string $path): array => [
				'path' => $path,
				'text' => self::explain($path, $l),
				'answeredBy' => TrapPaths::answeredBy($path),
			], TrapPaths::BUILTIN),
			'autodiscover' => $autodiscover,
			'autodiscoverPath' => TrapPaths::AUTODISCOVER,
			'custom' => $custom,
			'webServer' => $webServer,
			'needRule' => TrapPaths::needingRule($webServer, $builtinEnabled, $autodiscover, $custom),
			'max' => TrapPaths::MAX_CUSTOM,
			'snippets' => [
				['id' => 'nginx', 'file' => $snippets['nginx']['file'], 'content' => $snippets['nginx']['content']],
				['id' => 'apache', 'file' => $snippets['apache']['file'], 'content' => $snippets['apache']['content']],
			],
			'snippetsSkipped' => $snippets['skipped'],
		];
	}

	/**
	 * What a scanner looks for with a built-in trap path.
	 */
	public static function explain(string $path, IL10N $l): string {
		return match ($path) {
			'/wp-login.php', '/wp-admin' => $l->t('The WordPress login and admin area, tried with stolen or guessed passwords.'),
			'/xmlrpc.php' => $l->t('The WordPress remote interface, used to guess many passwords in one request.'),
			'/.env' => $l->t('Configuration files of web frameworks, which often contain database passwords and keys.'),
			'/.git/' => $l->t('A Git repository published by mistake, which reveals the source code and its secrets.'),
			'/.aws/' => $l->t('Amazon Web Services credentials left in the web root.'),
			'/phpmyadmin', '/pma' => $l->t('phpMyAdmin, a database tool that is often left open.'),
			'/adminer.php' => $l->t('Adminer, a one-file database tool.'),
			'/vendor/phpunit/' => $l->t('A test tool of PHP projects with a known flaw that runs any code.'),
			'/cgi-bin/' => $l->t('Old server scripts, probed for flaws such as Shellshock.'),
			'/boaform/' => $l->t('The admin page of cheap routers, attacked by botnets such as Mirai.'),
			'/hnap1' => $l->t('A router management interface with known flaws.'),
			'/actuator/' => $l->t('Spring Boot\'s monitoring endpoints, which can leak secrets.'),
			'/server-status' => $l->t('Apache\'s status page, which reveals visitors and requests.'),
			'/config.json' => $l->t('Configuration files left in the web root.'),
			'/.ds_store' => $l->t('macOS folder files that reveal which files exist.'),
			'/owa/', '/ecp/' => $l->t('Microsoft Exchange webmail and admin pages, attacked through known flaws.'),
			default => $l->t('A path no Nextcloud client requests.'),
		};
	}
}
