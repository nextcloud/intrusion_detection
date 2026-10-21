<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\IConfig;
use OCP\Security\ISecureRandom;

/**
 * The settings and state of the shared blocklist contribution.
 *
 * The feature exists only while config.php has
 * `intrusion_detection.contribution_available` set to true, because the
 * receiving service does not exist yet. Until then nothing is sent, nothing
 * can be switched on, and the settings are not shown.
 */
class ContributionSettings {
	public const SYSTEM_KEY = 'intrusion_detection.contribution_available';
	public const ID_LENGTH = 32;

	public function __construct(
		private readonly IConfig $config,
		private readonly Settings $settings,
		private readonly UrlPolicy $urlPolicy,
		private readonly ISecureRandom $random,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Read from config.php, without a database query.
	 */
	public function isAvailable(): bool {
		return $this->config->getSystemValueBool(self::SYSTEM_KEY, false);
	}

	/**
	 * Whether the admin switched the contribution on, and it is available.
	 */
	public function isEnabled(): bool {
		return $this->isAvailable() && $this->settings->getBool(GlobalSettings::CONTRIBUTE_ENABLED);
	}

	public function url(): string {
		return (string)$this->settings->global(GlobalSettings::CONTRIBUTE_URL);
	}

	/**
	 * @throws InvalidParamException
	 */
	public function setEnabled(bool $enabled, string $actor): void {
		$this->requireAvailable();
		$this->settings->setGlobal(GlobalSettings::CONTRIBUTE_ENABLED, $enabled);
		$this->audit->log('shared blocklist contribution %s by %s', ['state' => $enabled ? 'enabled' : 'disabled', 'actor' => $actor]);
	}

	/**
	 * Set where reports are sent: an `https://` address outside the local
	 * network, without credentials ({@see UrlPolicy}). The empty string
	 * removes the address.
	 *
	 * @throws InvalidParamException
	 */
	public function setUrl(string $url, string $actor): void {
		$this->requireAvailable();
		$url = trim($url);
		if ($url !== '' && !$this->urlPolicy->isAllowed($url)) {
			throw new InvalidParamException('contribution_url_refused');
		}
		$this->settings->setGlobal(GlobalSettings::CONTRIBUTE_URL, $url);
		$this->audit->log('shared blocklist contribution address set to %s by %s', ['url' => $url, 'actor' => $actor]);
	}

	/**
	 * The random id that tells the receiving service which reports come from
	 * the same server. Generated once; unrelated to the instance id.
	 */
	public function contributorId(): string {
		$id = (string)$this->settings->global(GlobalSettings::CONTRIBUTE_ID);
		if ($id === '') {
			$id = $this->random->generate(self::ID_LENGTH, ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS);
			$this->settings->setGlobal(GlobalSettings::CONTRIBUTE_ID, $id);
		}
		return $id;
	}

	public function state(): ContributionState {
		return ContributionState::fromArray($this->settings->getJson(GlobalSettings::CONTRIBUTE_STATE));
	}

	public function saveState(ContributionState $state): void {
		$this->settings->setGlobal(GlobalSettings::CONTRIBUTE_STATE, json_encode($state->toArray(), JSON_UNESCAPED_SLASHES));
	}

	/**
	 * @throws InvalidParamException
	 */
	private function requireAvailable(): void {
		if (!$this->isAvailable()) {
			throw new InvalidParamException('contribution_unavailable');
		}
	}
}
