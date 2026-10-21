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
use OCA\IntrusionDetection\Check\ParamText;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCP\IL10N;

/**
 * A logged-in account that reads the user directory faster than a person
 * does (concept section 10.16): searches, profiles and avatars, the system
 * address book, the user lists. A scraping account is compromised or an
 * insider, so the account itself is not told by default.
 *
 * The counting is {@see DirectoryScrapingDetector}, in the memory cache:
 * without one the check is unavailable, because counting in the database
 * would cost a write per request. The requests that count are
 * {@see DirectoryRoutes}.
 */
final class DirectoryScraping implements ICheck, IExplainsDetection, IExplainsToUser, IHeadlinesDetection {
	public const ID = 'directory_scraping';
	/** Read on the counting path without building the definition */
	public const DEFAULT_MODE = Mode::Protect;
	/** The counting window: fixed 10-minute buckets */
	public const WINDOW = 600;

	/**
	 * The limit per group: parameter name, default, minimum and maximum.
	 * The counting path reads these without building the definition.
	 */
	public const LIMITS = [
		DirectoryRoutes::GROUP_SEARCH => ['limit_search', 200, 10, 100000],
		DirectoryRoutes::GROUP_PROFILE => ['limit_profile', 1000, 10, 100000],
		DirectoryRoutes::GROUP_ADDRESSBOOK => ['limit_addressbook', 60, 5, 100000],
		DirectoryRoutes::GROUP_USERS => ['limit_users', 100, 5, 100000],
	];

	#[\Override]
	public function definition(): CheckDefinition {
		$params = [];
		foreach (self::LIMITS as [$name, $default, $min, $max]) {
			$params[] = new ParamDefinition($name, ParamType::Int, $default, min: $min, max: $max);
		}
		return new CheckDefinition(
			id: self::ID,
			category: Category::InsideTheAccount,
			defaultMode: self::DEFAULT_MODE,
			severity: Severity::Medium,
			params: $params,
			responses: [ResponseType::RateLimit, ResponseType::KillSession, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::RateLimit, ResponseType::NotifyAdmin],
			cost: CostClass::EveryRequestTiny,
			stores: [DataKind::CacheCounters, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Directory scraping'),
				summary: $l->t('A logged-in account that reads the list of people on this server faster than a person could.'),
				detects: $l->t('Someone who got into one account can copy the whole user directory: names, email addresses, phone numbers and pictures of everyone, for phishing or to sell. They do it by searching for one letter after the other, opening profile after profile, or downloading the address book over and over.'),
				decides: $l->t('Counts the requests of each account within 10 minutes and fires when one kind goes above its limit: {limit_search} searches for people (autocomplete, the sharing dialog, the contacts menu, unified search), {limit_profile} profile pages and avatars, {limit_addressbook} downloads of the system address book or the user list over WebDAV, and {limit_users} user lists of the user management.'),
				wrong: $l->t('A large shared folder or a long chat shows many avatars at once, which is why that limit is high. Address book apps sync now and then, but not dozens of times in 10 minutes. Raise a limit if an integration of yours searches a lot.'),
				data: $l->t('Counters per account and kind of request in the memory cache, for 10 minutes. Detections: the account, the address, the kind of request and the count.'),
				params: [
					'limit_search' => new ParamText($l->t('Searches'), $l->t('Searches for people within 10 minutes: autocomplete, the sharing dialog, the contacts menu, and unified search for people.'), $l->t('requests')),
					'limit_profile' => new ParamText($l->t('Profiles and avatars'), $l->t('Profile pages and avatars of accounts within 10 minutes. Pages with many people load many avatars, so keep this high.'), $l->t('requests')),
					'limit_addressbook' => new ParamText($l->t('Address book downloads'), $l->t('Requests to the system address book or the user list over WebDAV within 10 minutes.'), $l->t('requests')),
					'limit_users' => new ParamText($l->t('User lists'), $l->t('Requests for user lists of the user management within 10 minutes. Only administrators and group administrators can make them.'), $l->t('requests')),
				],
				cost: $l->t('One memory-cache increment on search, profile, address book and user list requests only; nothing on any other request. Needs a memory cache. With APCu only, each web server counts its own requests.'),
			),
			requirements: [Requirement::MemoryCache],
		);
	}

	/**
	 * The kind of request in the words of the admin page, e.g. "searches for people".
	 */
	public static function groupLabel(string $group, IL10N $l): string {
		return match ($group) {
			DirectoryRoutes::GROUP_SEARCH => $l->t('searches for people'),
			DirectoryRoutes::GROUP_PROFILE => $l->t('requests for profiles and avatars'),
			DirectoryRoutes::GROUP_ADDRESSBOOK => $l->t('downloads of the address book or the user list'),
			DirectoryRoutes::GROUP_USERS => $l->t('requests for user lists'),
			default => $group,
		};
	}

	#[\Override]
	public function headline(Detection $detection, IL10N $l): ?string {
		return $l->t('%s is reading the user directory unusually fast', [(string)$detection->getUid()]);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [
			$l->t('The account %1$s made %2$s %3$s within %4$s, from %5$s. The limit at that time was %6$s.', [
				(string)$detection->getUid(),
				(string)$facts->int('count'),
				self::groupLabel($facts->string('group'), $l),
				TextRenderer::duration($facts->int('window', self::WINDOW), $l),
				(string)$detection->getIp(),
				(string)$facts->int('limit'),
			]),
			$l->t('People do not read the directory this fast. The account may be used to copy the list of people on this server, by someone who got into it or by its owner.'),
		];
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It went above a limit again %n more time within the hour.', 'It went above a limit again %n more times within the hour.', $detection->getHits() - 1);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		return new UserNotice(
			$l->t('Unusually many searches from your account'),
			[$l->t('Your account searched for people or opened profiles much faster than a person does. Further requests of this kind are refused for a few minutes.')],
			[$l->t('If you did not do this, change your password now and check your devices and app passwords in your security settings.')],
		);
	}
}
