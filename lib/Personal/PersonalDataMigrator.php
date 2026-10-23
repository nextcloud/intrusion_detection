<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\UserMigration\IExportDestination;
use OCP\UserMigration\IImportSource;
use OCP\UserMigration\IMigrator;
use OCP\UserMigration\TMigratorBasicVersionHandling;
use OCP\UserMigration\UserMigrationException;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The user's own security data in a user export (the User migration app):
 * their logins, remembered devices, trusted networks, security changes and
 * the security events about their account, with the fields their security
 * page shows, as kept on this server.
 *
 * Nothing is imported: these records describe what happened on the server
 * that made them.
 */
class PersonalDataMigrator implements IMigrator {
	use TMigratorBasicVersionHandling;

	public const PATH = Application::APP_ID . '/security.json';
	/** The most logins, security changes and detections exported */
	public const MAX_ROWS = 10000;

	public function __construct(
		private readonly LoginHistory $loginHistory,
		private readonly PersonalActivity $activity,
		private readonly KnownDevices $knownDevices,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly SecurityChangeMapper $changes,
		private readonly PersonalDetections $detections,
		private readonly UserMessages $messages,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly IFactory $l10nFactory,
	) {
	}

	#[\Override]
	public function export(IUser $user, IExportDestination $exportDestination, OutputInterface $output): void {
		$output->writeln('Exporting the security data of intrusion detection…');
		$l = $this->messages->l10nFor($user);
		$data = $this->messages->asReader($user, $l, fn (): array => $this->data($user, $l));
		try {
			$exportDestination->addFileContents(self::PATH, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
		} catch (\Throwable $e) {
			throw new UserMigrationException('Could not export the security data of intrusion detection', 0, $e);
		}
	}

	#[\Override]
	public function import(IUser $user, IImportSource $importSource, OutputInterface $output): void {
		$output->writeln('The security data of intrusion detection is not imported: it describes what happened on the server that exported it.');
	}

	#[\Override]
	public function getId(): string {
		return Application::APP_ID;
	}

	#[\Override]
	public function getDisplayName(): string {
		return $this->l10nFactory->get(Application::APP_ID)->t('Security events');
	}

	#[\Override]
	public function getDescription(): string {
		return $this->l10nFactory->get(Application::APP_ID)->t('Your logins, remembered devices, trusted networks, security changes and the security events about your account, as your security page shows them. They are not imported on another server.');
	}

	/**
	 * @return array<string, mixed>
	 */
	private function data(IUser $user, IL10N $l): array {
		$uid = $user->getUID();
		$now = $this->timeFactory->getTime();
		$since = $now - $this->settings->retentionDays() * 86400;
		$waitedOutBefore = $this->activity->waitedOutBefore();
		return [
			'exportedAt' => $now,
			'logins' => array_map(
				static fn (LoginHistoryEntry $e): array => PersonalActivity::login($e, null, $waitedOutBefore, $l),
				$this->loginHistory->forUser($uid, $since, null, self::MAX_ROWS),
			),
			'knownDevices' => $this->knownDevices->forUser($uid, $l),
			'trustedNetworks' => $this->trustedNetworks->forUser($uid),
			'securityChanges' => array_map(
				static fn (array $row): array => SecureAccountOverview::change($row, $l),
				$this->changes->findRecent($uid, $since, self::MAX_ROWS),
			),
			'detections' => array_map(
				fn (Detection $d): array => $this->detections->present($d, $user),
				$this->detections->find($user, $since, self::MAX_ROWS),
			),
		];
	}
}
