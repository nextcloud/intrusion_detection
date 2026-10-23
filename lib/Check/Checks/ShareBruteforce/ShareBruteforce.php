<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ShareBruteforce;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\DigestSection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Guessing share link tokens, or the password of one share (concept
 * section 10.9). The detector is {@see ShareBruteforceDetector}.
 *
 * Token guessing and password guessing from one address block that
 * address. Password guessing on one share from any addresses tells the
 * people who manage the share ({@see userNotice()}) and the admins.
 * Unknown tokens opened while logged in, or from a server this one shares
 * files with ({@see \OCA\IntrusionDetection\Share\FederationPartners}),
 * are reported but never block the address.
 */
final class ShareBruteforce implements ICheck, IExplainsDetection, IExplainsToUser, ISimulatable, ISelectsResponses {
	public const ID = 'share_bruteforce';

	/** The responses of the rules about one address */
	private const SOURCE_RESPONSES = [ResponseType::Ban, ResponseType::NotifyAdmin];
	/** The responses of the rule about one share attacked from anywhere */
	private const SHARE_RESPONSES = [ResponseType::NotifyShareOwner, ResponseType::NotifyAdmin];

	public function __construct(
		private readonly DateFormatter $dates,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::SharesAndReset,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				// Below 3, one or two outdated links could fire it.
				new ParamDefinition('token_min', ParamType::Int, 10, min: 3, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('token_window', ParamType::Duration, 600, min: 60, max: 3600),
				new ParamDefinition('net_factor', ParamType::Int, 3, min: 1, max: 100),
				new ParamDefinition('password_min_per_source', ParamType::Int, 5, min: 2, max: 1000, preset: ParamPreset::Limit),
				new ParamDefinition('password_source_window', ParamType::Duration, 600, min: 60, max: 3600),
				new ParamDefinition('password_min_per_share', ParamType::Int, 20, min: 3, max: 10000, preset: ParamPreset::Limit),
				new ParamDefinition('password_share_window', ParamType::Duration, 3600, min: 300, max: 3600),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner],
			defaultResponses: [ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyShareOwner],
			cost: CostClass::OnFailureOnly,
			requirements: [Requirement::ShareAccessEvent],
			stores: [DataKind::FailedAttempts, DataKind::Detections, DataKind::Bans, DataKind::Flags],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Share link attacks'),
				shortName: $l->t('Share link attack'),
				summary: $l->t('Someone tries share links at random, or guesses the password of a share.'),
				detects: $l->t('A share link works like a secret address: whoever knows it can open the share. Attackers try random links in the hope of finding shared files, or try one password after the other on a link that is protected by a password.'),
				decides: $l->t('Fires when one address opens {token_min} different share links that do not exist within {token_window}; a whole /24 network is held to {net_factor} times this number. One or two outdated links never count. It also fires when one address enters {password_min_per_source} wrong passwords for one share within {password_source_window}, and when one share gets {password_min_per_share} wrong passwords from any number of addresses within {password_share_window}. The first two block the address; the last one tells the person who shared the link. Administrators are notified of each of them, if you choose so below.'),
				wrong: $l->t('Someone with old bookmarks to deleted shares, or a link checker that walks through many outdated links. People behind one office address who mistype a share\'s password many times: the person who shared it can send them the password again. When the server is flooded with failed attempts, only one in ten unknown links is recorded and the numbers are estimates, so nobody with one or two outdated links is affected. Unknown links opened while logged in are counted and reported, with the account, but never block the address, and a browser that opens links for another website or an email does not get its address blocked. A server your users share files with may keep opening federated shares that were deleted here, for example together with the account that shared them: an address that opened a federated share of this server within the last day is reported, but never blocked.'),
				data: $l->t('Failed share accesses: the address, a fingerprint of the link (never the link itself), the share for wrong passwords, and the time, deleted after 1 hour. Detections keep the share\'s id and the accounts that manage it, never its name or link. Addresses that opened a federated share of this server, kept at most 1 day after the last time.'),
			),
			simulatable: true,
			honoursLure: true,
			digestSection: DigestSection::Shares,
		);
	}

	/**
	 * A link a logged-in user opened is reported, never a reason to block:
	 * the account is known, and blocking would lock its owner out. The same
	 * for links a partner server opened: blocking it would cut off the
	 * federated shares it still has.
	 */
	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$facts = ShareBruteforceFacts::fromArray($draft->facts);
		$allowed = $facts->rule === ShareBruteforceRule::PasswordShare ? self::SHARE_RESPONSES : self::SOURCE_RESPONSES;
		$spared = $facts->loggedIn === true || $facts->federation === true;
		return array_values(array_filter($configured, static fn (ResponseType $r): bool => in_array($r, $allowed, true) && !($spared && $r === ResponseType::Ban)));
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$stored = DetectionFacts::of($detection);
		$facts = ShareBruteforceFacts::fromArray($stored->facts);
		$from = $this->dates->dateTime($stored->first);
		$to = $this->dates->time($stored->last);
		$sentences = [];

		switch ($facts->rule ?? ShareBruteforceRule::Tokens) {
			case ShareBruteforceRule::PasswordSource:
				$sentences[] = $l->t('Between %1$s and %2$s the address %3$s entered %4$s wrong passwords for a share of %5$s (share %6$s).', [
					$from, $to, (string)$detection->getIp(), (string)($facts->failures ?? 0), $facts->owner ?? '', (string)$detection->getShareId(),
				]);
				$sentences[] = $l->t('The limit at that time was %1$s wrong passwords for one share within %2$s.', [
					(string)$stored->threshold('password_min_per_source'),
					TextRenderer::duration($stored->threshold('password_source_window', 600), $l),
				]);
				break;
			case ShareBruteforceRule::PasswordShare:
				$sentences[] = $l->t('Between %1$s and %2$s a share of %3$s (share %4$s) got %5$s wrong passwords from %6$s different addresses.', [
					$from, $to, $facts->owner ?? '', (string)$detection->getShareId(), (string)($facts->failures ?? 0), (string)($facts->sources ?? 0),
				]);
				$sentences[] = $l->t('The limit at that time was %1$s wrong passwords for one share within %2$s, from any number of addresses.', [
					(string)$stored->threshold('password_min_per_share'),
					TextRenderer::duration($stored->threshold('password_share_window', 3600), $l),
				]);
				if (($facts->lastSource ?? '') !== '') {
					$sentences[] = $l->t('The most recent attempt came from %s.', [$facts->lastSource]);
				}
				break;
			case ShareBruteforceRule::TokensNetwork:
				$sentences[] = $l->t('Between %1$s and %2$s the network %3$s tried %4$s different share links that do not exist, from %5$s addresses.', [
					$from, $to, $facts->net ?? (string)$detection->getNetKey(), TextRenderer::estimated($facts->tokens ?? 0, $facts->sampleFactor, $l), (string)($facts->sources ?? 0),
				]);
				$sentences[] = $l->t('The limit for a network at that time was %1$s links within %2$s.', [
					(string)($stored->threshold('token_min') * max(1, $stored->threshold('net_factor', 3))),
					TextRenderer::duration($stored->threshold('token_window', 600), $l),
				]);
				break;
			case ShareBruteforceRule::Tokens:
				$sentences[] = $l->t('Between %1$s and %2$s the address %3$s tried %4$s different share links that do not exist (%5$s attempts).', [
					$from, $to, (string)$detection->getIp(), TextRenderer::estimated($facts->tokens ?? 0, $facts->sampleFactor, $l), TextRenderer::estimated($facts->attempts ?? 0, $facts->sampleFactor, $l),
				]);
				$sentences[] = $l->t('The limit at that time was %1$s links within %2$s.', [
					(string)$stored->threshold('token_min'),
					TextRenderer::duration($stored->threshold('token_window', 600), $l),
				]);
		}
		if ($facts->loggedIn === true && $detection->getUid() !== null) {
			$sentences[] = $l->t('The most recent of these links was opened while logged in as %s. Links opened while logged in are reported, but never block the address.', [$detection->getUid()]);
		}
		if ($facts->federation === true) {
			$sentences[] = $l->t('The address opened a federated share of this server within the last day: it belongs to a server your users share files with, which may still open federated shares that were deleted here. Such an address is reported, but never blocked.');
		}
		$partners = $facts->partners ?? 0;
		if ($partners > 0) {
			$sentences[] = $l->n(
				'%n address of the network opened a federated share of this server within the last day and was not blocked.',
				'%n addresses of the network opened a federated share of this server within the last day and were not blocked.',
				$partners,
			);
		}
		$factor = $facts->sampleFactor ?? 1;
		if ($factor > 1) {
			$sentences[] = $l->t('The server was receiving so many failed attempts that only one in %s unknown links was recorded. The numbers are estimates from those.', [(string)$factor]);
		}
		return $sentences;
	}

	/**
	 * The notice for the people who manage a share whose password is being
	 * guessed. The share's name is read from the share now; it is not stored.
	 */
	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$stored = DetectionFacts::of($detection);
		$facts = ShareBruteforceFacts::fromArray($stored->facts);
		$links = $this->container->get(ShareLinks::class);
		$share = $links->find($detection);
		$failures = $facts->failures ?? 0;
		$window = TextRenderer::duration($facts->rule === ShareBruteforceRule::PasswordSource
			? $stored->threshold('password_source_window', 600)
			: $stored->threshold('password_share_window', 3600), $l);
		$message = [
			$share !== null
				? $l->n(
					'Someone is trying to guess the password of your share "%1$s" (%n wrong password within %2$s).',
					'Someone is trying to guess the password of your share "%1$s" (%n wrong passwords within %2$s).',
					$failures,
					[$links->displayName($share), $window],
				)
				: $l->n(
					'Someone was trying to guess the password of one of your shares (%n wrong password within %1$s). The share no longer exists.',
					'Someone was trying to guess the password of one of your shares (%n wrong passwords within %1$s). The share no longer exists.',
					$failures,
					[$window],
				),
		];
		if ($share !== null) {
			$message[] = $l->t('If the password is short, change it, or turn the link off.');
		}
		return new UserNotice($l->t('Someone is trying to guess the password of your share'), $message);
	}

	#[\Override]
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft {
		$tokens = (int)($params['token_min'] ?? 10);
		return new DetectionDraft(
			checkId: self::ID,
			source: $source,
			facts: new ShareBruteforceFacts(
				rule: ShareBruteforceRule::Tokens,
				tokens: $tokens,
				attempts: $tokens,
				sampleFactor: 1,
				common: new CommonFacts(first: $now - (int)($params['token_window'] ?? 600) + 60, last: $now, simulated: true),
			),
			merge: DetectionDraft::MERGE_SOURCE,
		);
	}
}
