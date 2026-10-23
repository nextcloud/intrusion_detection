<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\IL10N;

/**
 * One app password, password or browser session used from two networks at
 * the same time (concept section 10.12), as happens when someone copied
 * it. The guard is {@see \OCA\IntrusionDetection\Guard\CredentialUseGuard},
 * the switching rule {@see \OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialHistory},
 * the recording {@see TokenConcurrentUseDetector}.
 */
final class TokenConcurrentUse implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'token_concurrent_use';
	/** Read by the guard without building the definition */
	public const DEFAULT_MODE = Mode::Protect;

	public const PARAM_WINDOW = 'window';
	public const PARAM_MIN_SWITCHES = 'min_switches';

	/** An app password or token, over Basic or Bearer */
	public const KIND_APP_PASSWORD = 'app_password';
	/** The account's login password over Basic */
	public const KIND_PASSWORD = 'password';
	/** A logged-in browser session (its cookie) */
	public const KIND_SESSION = 'session';

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::DevicesAndSessions,
			defaultMode: self::DEFAULT_MODE,
			severity: Severity::Medium,
			params: [
				new ParamDefinition(self::PARAM_WINDOW, ParamType::Duration, 900, min: 60, max: 3600),
				new ParamDefinition(self::PARAM_MIN_SWITCHES, ParamType::Int, 3, min: 2, max: 20, preset: ParamPreset::Limit),
			],
			responses: [ResponseType::RevokeToken, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			cost: CostClass::EveryRequestTiny,
			stores: [DataKind::CacheCounters, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Stolen app password or session'),
				shortName: $l->t('Stolen session'),
				summary: $l->t('One app password or logged-in session used from two networks at the same time.'),
				detects: $l->t('An app password or a logged-in browser session that is used from two different networks at the same time, as happens when someone copied it: from a computer, a backup or a browser. The real owner keeps using it, and so does the person who copied it. The same applies to a password that apps send with every request.'),
				decides: $l->t('Fires when the same credential switches back and forth between two networks at least {min_switches} times within {window}. A phone moving from Wi-Fi to mobile data switches once and is not counted. Switching between IPv4 and IPv6 is ignored. A credential that does not log in is never reported.'),
				wrong: $l->t('A phone at the edge of a Wi-Fi network that keeps switching to mobile data and back, a VPN that is switched on and off repeatedly, or one app password that is used on purpose on two computers in different places. Also a server behind several proxies that are not set up as trusted proxies, because then it sees the proxies\' addresses instead of the users\'. The user is asked "Was this you?", and nothing is revoked unless you switch that on.'),
				data: $l->t('In the memory cache only, for up to an hour: for each credential a keyed fingerprint and the last few networks it was used from. The credential itself is never stored. Detections: both addresses, the name of the app password or session, and the account.'),
				params: [
					self::PARAM_WINDOW => new ParamText($l->t('Time window'), $l->t('The switches must happen within this time.')),
					self::PARAM_MIN_SWITCHES => new ParamText($l->t('Switches'), $l->t('How often the credential must switch between the same two networks. 3 means from A to B, back to A and to B again.'), $l->t('switches')),
				],
				cost: $l->t('A cache write only when the network changes, or every five minutes. With APCu only, each web server sees only its own requests, so uses on two different web servers are not noticed.'),
			),
			requirements: [Requirement::MemoryCache, Requirement::RequestGuards],
		);
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$stored = DetectionFacts::of($detection);
		$facts = TokenConcurrentUseFacts::fromArray($stored->facts);
		$uid = (string)$detection->getUid();
		$ip1 = $facts->ip1;
		$ip2 = $facts->ip2;
		$name = TextRenderer::defused($facts->tokenName);
		$sentences = [match ($facts->kind) {
			self::KIND_SESSION => $name === ''
				? $l->t('A logged-in browser session of the account %1$s was used from two different networks at the same time: %2$s and %3$s.', [$uid, $ip1, $ip2])
				: $l->t('The logged-in browser session "%1$s" of the account %2$s was used from two different networks at the same time: %3$s and %4$s.', [$name, $uid, $ip1, $ip2]),
			self::KIND_PASSWORD => $l->t('The password of the account %1$s was sent by an app from two different networks at the same time: %2$s and %3$s.', [$uid, $ip1, $ip2]),
			default => $name === ''
				? $l->t('An app password of the account %1$s was used from two different networks at the same time: %2$s and %3$s.', [$uid, $ip1, $ip2])
				: $l->t('The app password "%1$s" of the account %2$s was used from two different networks at the same time: %3$s and %4$s.', [$name, $uid, $ip1, $ip2]),
		}];
		$switches = $facts->switches;
		$sentences[] = $l->n(
			'It switched between these two networks %n time within %1$s. The limit at that time was %2$s switches within %3$s.',
			'It switched between these two networks %n times within %1$s. The limit at that time was %2$s switches within %3$s.',
			$switches,
			[
				TextRenderer::duration(self::roundedSpan(($facts->common->last ?? 0) - ($facts->common->first ?? 0)), $l),
				(string)$stored->threshold(self::PARAM_MIN_SWITCHES, 3),
				TextRenderer::duration($stored->threshold(self::PARAM_WINDOW, 900), $l),
			],
		);
		$sentences[] = $l->t('It logged in successfully, so whoever used it from the other network had a working copy.');
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It happened again %n more time within the hour.', 'It happened again %n more times within the hour.', $detection->getHits() - 1);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = TokenConcurrentUseFacts::fromArray(DetectionFacts::of($detection)->facts);
		$ip1 = $facts->ip1;
		$ip2 = $facts->ip2;
		$device = DeviceLabel::describe($facts->tokenName, $l);
		$appPassword = UserMessages::appPassword($facts->tokenName, $l);
		return match ($facts->kind) {
			self::KIND_SESSION => new UserNotice(
				$l->t('Your session was used from two places at once'),
				[
					$device === null
						? $l->t('Your logged-in session was used from two different networks at the same time: %1$s and %2$s.', [$ip1, $ip2])
						: $l->t('Your logged-in session (%1$s) was used from two different networks at the same time: %2$s and %3$s.', [$device, $ip1, $ip2]),
					$l->t('This happens when someone copied it from your browser.'),
				],
				[$l->t('If this was not you, answer "No, it was not me": the session is then ended. Log out of all other sessions in your security settings and change your password.')],
			),
			self::KIND_PASSWORD => new UserNotice(
				$l->t('Your password was used from two places at once'),
				[
					$l->t('Your password was sent by an app from two different networks at the same time: %1$s and %2$s.', [$ip1, $ip2]),
					$l->t('This happens when someone else knows your password.'),
				],
				[$l->t('If this was not you, change your password now and use app passwords for your apps.')],
			),
			default => new UserNotice(
				$l->t('Your app password was used from two places at once'),
				[
					$appPassword === null
						? $l->t('One of your app passwords was used from two different networks at the same time: %1$s and %2$s.', [$ip1, $ip2])
						: $l->t('Your app password %1$s was used from two different networks at the same time: %2$s and %3$s.', [$appPassword, $ip1, $ip2]),
					$l->t('This happens when someone copied it, for example from a computer or a backup.'),
				],
				[$l->t('If this was not you, answer "No, it was not me": the app password is then revoked and the sessions created with it end. Connect your own devices again afterwards and change your password.')],
			),
		};
	}

	/**
	 * Seconds below a minute, whole minutes (rounded up) above.
	 */
	private static function roundedSpan(int $seconds): int {
		return $seconds < 60 ? max(1, $seconds) : (int)ceil($seconds / 60) * 60;
	}
}
