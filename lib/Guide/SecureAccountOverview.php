<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guide;

use OC\Authentication\Token\IProvider as PrivateTokenProvider;
use OC\Authentication\Token\PublicKeyToken;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\App\IAppManager;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IToken;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\Share\IManager as IShareManager;
use OCP\Share\IShare;
use Psr\Log\LoggerInterface;

/**
 * What the "Secure my account" checklist shows its user (concept section
 * 15.3): the sessions and app passwords with where they were created, the
 * security changes and the public, email and federated shares since a week
 * before the event, and where to look further. Only the user's own data,
 * never a secret: tokens and share links appear only by id and name.
 *
 * @psalm-import-type IntrusionDetectionSecureAccount from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecurityChange from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecureAccountSession from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecureAccountShare from ResponseDefinitions
 * @psalm-import-type SecurityChangeRow from SecurityChangeMapper
 */
class SecureAccountOverview {
	public const MAX_SESSIONS = 100;
	public const MAX_CHANGES = 50;
	public const MAX_SHARES = 50;
	/** Shares of each type looked at, newest pages first */
	private const SHARE_SCAN = 500;
	private const SHARE_TYPES = [IShare::TYPE_LINK, IShare::TYPE_EMAIL, IShare::TYPE_REMOTE, IShare::TYPE_REMOTE_GROUP];

	public function __construct(
		private readonly SecureAccountGuide $guide,
		private readonly SecurityChangeMapper $changes,
		private readonly TokenOriginMapper $origins,
		private readonly PrivateTokenProvider $tokens,
		private readonly CurrentSession $currentSession,
		private readonly IShareManager $shareManager,
		private readonly IAppManager $appManager,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return IntrusionDetectionSecureAccount
	 */
	public function forUser(IUser $user, IL10N $l): array {
		$progress = $this->guide->progress($user);
		$eventAt = $progress['eventAt'] ?? $this->timeFactory->getTime();
		$since = $eventAt - SecureAccountGuide::LOOK_BACK;
		$uid = $user->getUID();
		$email = (string)$user->getEMailAddress();
		return [
			'progress' => $progress,
			'since' => $since,
			'sessions' => $this->sessions($uid, $eventAt, $l),
			'changes' => array_map(fn (array $row): array => self::change($row, $l), $this->changes->findRecent($uid, $since, self::MAX_CHANGES)),
			'shares' => $this->shares($uid, $since),
			'email' => $email === '' ? null : $email,
			'canChangePassword' => $user->canChangePassword(),
			'links' => [
				'security' => $this->urlGenerator->linkToRouteAbsolute('settings.PersonalSettings.index', ['section' => 'security']),
				'personalInfo' => $this->urlGenerator->linkToRouteAbsolute('settings.PersonalSettings.index', ['section' => 'personal-info']),
				'activity' => $this->appManager->isEnabledForUser('activity', $user) ? $this->urlGenerator->linkToRouteAbsolute('activity.Activities.showList') : null,
				'trash' => $this->appManager->isEnabledForUser('files_trashbin', $user) ? $this->urlGenerator->linkToRouteAbsolute('files.view.indexView', ['view' => 'trashbin']) : null,
			],
		];
	}

	/**
	 * A security change as users and administrators read it.
	 *
	 * @param SecurityChangeRow $row
	 * @return IntrusionDetectionSecurityChange
	 */
	public static function change(array $row, IL10N $l): array {
		$type = SecurityChangeType::tryFrom($row['type']);
		return [
			'id' => $row['id'],
			'type' => $row['type'],
			'label' => $type?->label($l) ?? $row['type'],
			'via' => $row['via'],
			'actor' => $row['via'] === SecurityChangeLog::VIA_ADMIN ? $row['actor_uid'] : null,
			'previous' => $row['old_value_hint'],
			'new' => $row['new_value_hint'],
			'detail' => $row['detail'],
			'address' => $row['ip'],
			'createdAt' => $row['created_at'],
		];
	}

	/**
	 * @return list<IntrusionDetectionSecureAccountSession>
	 */
	private function sessions(string $uid, int $eventAt, IL10N $l): array {
		$current = $this->currentSession->tokenId();
		$sessions = [];
		try {
			$tokens = $this->tokens->getTokenByUser($uid);
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not list the sessions of {uid}', ['uid' => $uid, 'exception' => $e]);
			return [];
		}
		$tokens = array_values(array_filter($tokens, static fn (IToken $t): bool => $t->getType() === IToken::TEMPORARY_TOKEN || $t->getType() === IToken::PERMANENT_TOKEN));
		$origins = $this->origins->findMany(array_map(static fn (IToken $t): int => $t->getId(), $tokens));
		foreach ($tokens as $token) {
			$type = $token->getType();
			$origin = $origins[$token->getId()] ?? null;
			$lastActivity = $token instanceof PublicKeyToken ? $token->getLastActivity() : null;
			$sessions[] = [
				'id' => $token->getId(),
				'name' => $type === IToken::TEMPORARY_TOKEN ? self::browserName($token, $l) : Tokens::name($token),
				'kind' => $type === IToken::PERMANENT_TOKEN ? 'app_password' : 'session',
				'current' => $token->getId() === $current,
				'lastActivity' => $lastActivity,
				'createdAt' => $origin['created_at'] ?? null,
				'address' => $origin['ip'] ?? null,
				'afterEvent' => ($origin['created_at'] ?? 0) >= $eventAt || ($origin === null && $lastActivity !== null && $lastActivity >= $eventAt && $type === IToken::TEMPORARY_TOKEN),
			];
		}
		usort($sessions, static fn (array $a, array $b): int => [(int)$b['afterEvent'], $b['lastActivity'] ?? 0] <=> [(int)$a['afterEvent'], $a['lastActivity'] ?? 0]);
		return array_slice($sessions, 0, self::MAX_SESSIONS);
	}

	/**
	 * A browser session is named by its user agent; people recognise
	 * "Firefox on Linux" as on the personal page, not the raw string.
	 */
	private static function browserName(IToken $token, IL10N $l): string {
		[$family, $platform] = DeviceLabel::parse($token->getName());
		return $family === DeviceLabel::OTHER && $platform === DeviceLabel::OTHER ? Tokens::name($token) : DeviceLabel::translated($family, $platform, $l);
	}

	/**
	 * @return list<IntrusionDetectionSecureAccountShare>
	 */
	private function shares(string $uid, int $since): array {
		$found = [];
		foreach (self::SHARE_TYPES as $type) {
			try {
				$shares = $this->shareManager->getSharesBy($uid, $type, null, true, self::SHARE_SCAN, 0, false);
			} catch (\Throwable $e) {
				$this->logger->warning('Intrusion detection could not list the shares of type {type} of {uid}', ['type' => $type, 'uid' => $uid, 'exception' => $e]);
				continue;
			}
			foreach ($shares as $share) {
				$created = $share->getShareTime()->getTimestamp();
				if ($created < $since) {
					continue;
				}
				$found[] = [
					'id' => $share->getFullId(),
					'name' => basename($share->getTarget()),
					'type' => match ($type) {
						IShare::TYPE_LINK => 'link',
						IShare::TYPE_EMAIL => 'email',
						default => 'federated',
					},
					'recipient' => $type === IShare::TYPE_LINK ? null : (string)$share->getSharedWith(),
					'createdAt' => $created,
					'hasPassword' => ($share->getPassword() ?? '') !== '',
					'expiresAt' => $share->getExpirationDate()?->getTimestamp(),
					'isFolder' => $share->getNodeType() === 'folder',
				];
			}
		}
		usort($found, static fn (array $a, array $b): int => $b['createdAt'] <=> $a['createdAt']);
		return array_slice($found, 0, self::MAX_SHARES);
	}
}
