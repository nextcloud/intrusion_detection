<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\HeldChanges;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\IKeepsFromUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Tells every administrator about changes that give or take administration
 * rights or weaken security: new administrators, group administrators,
 * accounts created by administrators, apps switched on or off, and changes
 * of the watched security settings. Optionally, a second administrator must
 * approve every new administrator.
 *
 * The account a change was about is told only when its own administration
 * rights changed ({@see self::keepsFromUser()}). A grant held back for
 * approval runs no response: the approval request tells the administrators.
 *
 * The detector is {@see AdminChangeDetector}; the events come from
 * {@see \OCA\IntrusionDetection\Listener\AdminChangeListener} and
 * {@see \OCA\IntrusionDetection\AdminChange\ConfigWatch}.
 *
 * @psalm-import-type HeldChange from Approval
 */
final class AdminChange implements ICheck, IExplainsDetection, IHeadlinesDetection, IValidatesParams, IExplainsToUser, IKeepsFromUser, ISelectsResponses {
	public const ID = 'admin_change';

	public const KIND_ADMIN_GRANTED = 'admin_granted';
	public const KIND_GRANT_REQUESTED = 'admin_grant_requested';
	public const KIND_ADMIN_REMOVED = 'admin_removed';
	public const KIND_SUBADMIN_GRANTED = 'subadmin_granted';
	public const KIND_USER_CREATED = 'user_created';
	public const KIND_APP_ENABLED = 'app_enabled';
	public const KIND_APP_DISABLED = 'app_disabled';
	public const KIND_SETTING_CHANGED = 'setting_changed';

	/** Why a new administrator did not wait for approval */
	public const EXEMPT_OCC = 'occ';
	public const EXEMPT_CRON = 'cron';
	public const EXEMPT_DIRECTORY = 'directory';

	public function __construct(
		private readonly DateFormatter $dates,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Administration,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [],
			responses: [ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::NotifyAdmin],
			cost: CostClass::Background,
			stores: [DataKind::Detections, DataKind::ConfigSnapshot, DataKind::Approvals],
			globals: [GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL],
			heldByLock: true,
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Admin change alerts'),
				shortName: $l->t('Admin change'),
				summary: $l->t('Someone got administrator rights, an app was switched on or off, or a security setting changed.'),
				detects: $l->t('An intruder who gets into an administrator account usually makes themselves at home: they give a second account administrator rights, switch on an app, or weaken a security setting so that the next step is easier. This check tells every administrator about such changes, including the one who made them. If that account was taken over, its owner still learns what was done in their name.'),
				decides: $l->t('Fires on every change: an account added to the admin group or to a group with delegated administration settings, a group administrator appointed, an account created by an administrator, an app switched on or off, and every change of the watched security settings. Changes in config.php are found by a check every 5 minutes. A second administrator must approve new administrators, also members added to a group with delegated administration settings: {admin_change_require_approval}. A request for approval expires after %s.', [TextRenderer::duration(ApprovalService::TTL, $l)]),
				wrong: $l->t('It reports changes, not attacks: most of them are your own work. Every administrator gets them, so that nobody has to wonder whether a change was planned. With approval switched on, administrators added on the command line (occ) and memberships that come from a user directory such as LDAP do not wait for approval: whoever can run occ already controls the server, and Nextcloud cannot undo a membership the directory sets. Both are still reported.'),
				data: $l->t('Detections: who changed what and when, with the old and the new value. Values that Nextcloud treats as secret are never stored or shown; a keyed fingerprint tells that they changed. Requests for approval: who asked, for whom, the decision and who made it, kept 90 days after the decision.'),
			),
		);
	}

	/**
	 * Approval can only be switched on while a second administrator exists who
	 * could approve.
	 */
	#[\Override]
	public function validateParam(string $name, int|float|bool|string|array $value): int|float|bool|string|array {
		if ($name === GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL && $value === true && $this->container->get(Approvers::class)->count() < 2) {
			throw new InvalidParamException('too_few_admins', ['param' => $name]);
		}
		return $value;
	}

	/**
	 * What a settings change that waits for approval does, as one or two
	 * sentences for the approvers ({@see HeldChanges}).
	 *
	 * @param HeldChange $change
	 */
	public function heldChange(array $change, IL10N $l): string {
		$name = function () use ($change, $l): string {
			$registry = $this->container->get(CheckRegistry::class);
			$id = (string)($change['check'] ?? '');
			return $registry->has($id) ? $registry->get($id)->texts($l)->name : $id;
		};
		switch ($change['op']) {
			case HeldChanges::SETTINGS:
				$values = $change['values'] ?? [];
				$parts = [];
				if (array_key_exists(GlobalSettings::ENABLED, $values) && $values[GlobalSettings::ENABLED] !== true) {
					$parts[] = $l->t('Switch intrusion detection off.');
				}
				if (array_key_exists(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, $values) && $values[GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL] !== true) {
					$parts[] = $l->t('Stop asking a second administrator to approve new administrators.');
				}
				$others = count(array_diff(array_keys($values), [GlobalSettings::ENABLED, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL]));
				if ($others > 0) {
					$parts[] = $l->n('Change %n other setting.', 'Change %n other settings.', $others);
				}
				return implode(' ', $parts);
			case HeldChanges::CHECK:
				$mode = Mode::tryFrom((string)($change['mode'] ?? ''));
				return $mode === null
					? $l->t('Change "%s".', [$name()])
					: $l->t('Set "%1$s" to %2$s.', [$name(), $mode->label($l)]);
			case HeldChanges::RESET_CHECK:
				return $l->t('Put "%s" back to its defaults.', [$name()]);
			case HeldChanges::RESET_ALL:
				return $l->t('Put every setting back to its default, which switches off the approval of new administrators.');
			default:
				return $l->t('Change the settings.');
		}
	}

	#[\Override]
	public function headline(Detection $detection, IL10N $l): ?string {
		$facts = AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts);
		$subject = self::subject($detection, $facts);
		return match ($facts->kind) {
			self::KIND_ADMIN_GRANTED => ($facts->delegated ?? []) !== []
				? $l->t('%1$s got administration rights through the group "%2$s"', [$subject, $facts->group ?? ''])
				: $l->t('%s was made an administrator', [$subject]),
			self::KIND_GRANT_REQUESTED => ($facts->delegated ?? []) !== []
				? $l->t('Approval needed: %1$s to join "%2$s", which has administration rights', [$subject, $facts->group ?? ''])
				: $l->t('Approval needed: %s to become an administrator', [$subject]),
			self::KIND_ADMIN_REMOVED => ($facts->delegated ?? []) !== []
				? $l->t('%1$s left the group "%2$s", which has administration rights', [$subject, $facts->group ?? ''])
				: $l->t('%s is no longer an administrator', [$subject]),
			self::KIND_SUBADMIN_GRANTED => $l->t('%1$s was made a group administrator of "%2$s"', [$subject, $facts->group ?? '']),
			self::KIND_USER_CREATED => $l->t('The account %s was created', [$subject]),
			self::KIND_APP_ENABLED => $l->t('The app "%s" was switched on', [$facts->app ?? '']),
			self::KIND_APP_DISABLED => $l->t('The app "%s" was switched off', [$facts->app ?? '']),
			self::KIND_SETTING_CHANGED => $l->t('Security setting changed: %s', [$this->label($facts->setting ?? '', $l)]),
			default => null,
		};
	}

	#[\Override]
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array {
		$facts = AdminChangeFacts::fromArray($draft->facts);
		return $facts->kind === self::KIND_GRANT_REQUESTED && $facts->approval !== null ? [] : $configured;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts);
		$actor = self::actorName($facts->actor ?? ActorResolver::UNKNOWN, $l);
		$subject = self::subject($detection, $facts);
		$group = $facts->group ?? '';
		$delegated = $facts->delegated ?? [];
		$sentences = [];

		switch ($facts->kind) {
			case self::KIND_ADMIN_GRANTED:
				$sentences[] = $delegated !== []
					? $l->t('%1$s added %2$s to the group "%3$s", which has these administration settings: %4$s.', [$actor, $subject, $group, implode(', ', $delegated)])
					: $l->t('%1$s made %2$s an administrator.', [$actor, $subject]);
				if (($facts->approvedBy ?? '') !== '') {
					$sentences[] = $l->t('%1$s asked for it, and %2$s approved it.', [self::actorName($facts->requestedBy ?? ActorResolver::UNKNOWN, $l), $facts->approvedBy]);
				}
				$sentences = array_merge($sentences, $this->exemption($facts->exempt ?? '', $l));
				break;
			case self::KIND_GRANT_REQUESTED:
				$sentences[] = $delegated !== []
					? $l->t('%1$s tried to add %2$s to the group "%3$s", which has these administration settings: %4$s.', [$actor, $subject, $group, implode(', ', $delegated)])
					: $l->t('%1$s tried to make %2$s an administrator.', [$actor, $subject]);
				if ($facts->revertFailed === true) {
					$sentences[] = $delegated !== []
						? $l->t('A second administrator must approve new administrators, but Nextcloud could not take %1$s out of the group "%2$s" again. Check the members of that group now.', [$subject, $group])
						: $l->t('A second administrator must approve new administrators, but Nextcloud could not take %s out of the admin group again. Check the members of the admin group now.', [$subject]);
				} else {
					$sentences[] = $delegated !== []
						? $l->t('A second administrator must approve new administrators, so %1$s was taken out of the group "%2$s" again at once.', [$subject, $group])
						: $l->t('A second administrator must approve new administrators, so %s was taken out of the admin group again at once.', [$subject]);
					$sentences[] = $facts->approval !== null
						? $l->t('The request waits for the approval of another administrator until %s. Neither the one who asked nor the account itself can approve it.', [$this->dates->dateTime($facts->expiresAt ?? 0)])
						: $l->t('Too many requests are already waiting, so this one was not stored. Decide the open requests, then add the account again.');
				}
				break;
			case self::KIND_ADMIN_REMOVED:
				$sentences[] = $delegated !== []
					? $l->t('%1$s removed %2$s from the group "%3$s", which has these administration settings: %4$s.', [$actor, $subject, $group, implode(', ', $delegated)])
					: $l->t('%1$s removed %2$s from the administrators.', [$actor, $subject]);
				break;
			case self::KIND_SUBADMIN_GRANTED:
				$sentences[] = $l->t('%1$s made %2$s a group administrator of "%3$s". Group administrators manage the accounts of their group.', [$actor, $subject, $group]);
				break;
			case self::KIND_USER_CREATED:
				$sentences[] = $l->t('%1$s created the account %2$s.', [$actor, $subject]);
				break;
			case self::KIND_APP_ENABLED:
				$groups = $facts->groups ?? [];
				$sentences[] = $groups === []
					? $l->t('%1$s switched on the app "%2$s" for everyone.', [$actor, $facts->app ?? ''])
					: $l->t('%1$s switched on the app "%2$s" for the groups %3$s.', [$actor, $facts->app ?? '', implode(', ', $groups)]);
				break;
			case self::KIND_APP_DISABLED:
				$sentences[] = $l->t('%1$s switched off the app "%2$s".', [$actor, $facts->app ?? '']);
				if ($facts->app === Application::APP_ID) {
					$sentences[] = $l->t('This switches off intrusion detection itself: nothing is watched or blocked any more until it is switched on again.');
				}
				break;
			case self::KIND_SETTING_CHANGED:
				$sentences = $this->settingSentences($facts, $actor, $l);
				break;
			default:
				$sentences[] = $l->t('An administration setting was changed.');
		}

		$ip = $facts->actorIp ?? '';
		if ($ip !== '') {
			$sentences[] = $l->t('The change came from the address %s.', [$ip]);
		}
		$sentences[] = $l->t('It happened at %s.', [$this->dates->dateTime($detection->getCreatedAt())]);
		return $sentences;
	}

	/**
	 * Told only when the account's own administration rights changed. Its
	 * creation is no security event for its new owner, a request that waits
	 * for approval has not changed anything yet, and the other changes are
	 * about no account.
	 */
	#[\Override]
	public function keepsFromUser(Detection $detection): bool {
		return !in_array(AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts)->kind, [self::KIND_ADMIN_GRANTED, self::KIND_ADMIN_REMOVED, self::KIND_SUBADMIN_GRANTED], true);
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = AdminChangeFacts::fromArray(DetectionFacts::of($detection)->facts);
		$group = $facts->group ?? '';
		$delegated = ($facts->delegated ?? []) !== [];
		$advice = [$l->t('If you did not expect this, ask your administrators about it.')];
		return match ($facts->kind) {
			self::KIND_ADMIN_GRANTED => $delegated
				? new UserNotice($l->t('You got administration rights'), [$l->t('You were added to the group "%s", which has administration rights for some settings.', [$group])], $advice)
				: new UserNotice($l->t('You were made an administrator'), [$l->t('An administrator made you an administrator. You can now manage all accounts and settings.')], $advice),
			self::KIND_ADMIN_REMOVED => $delegated
				? new UserNotice($l->t('You left a group with administration rights'), [$l->t('You were removed from the group "%s", which has administration rights for some settings.', [$group])], $advice)
				: new UserNotice($l->t('You are no longer an administrator'), [$l->t('An administrator removed you from the administrators.')], $advice),
			self::KIND_SUBADMIN_GRANTED => new UserNotice($l->t('You were made a group administrator'), [$l->t('An administrator made you a group administrator of "%s". You can now manage the accounts of that group.', [$group])], $advice),
			self::KIND_USER_CREATED => new UserNotice($l->t('Your account was created'), [$l->t('An administrator created your account.')], $advice),
			default => new UserNotice($l->t('Your administration rights changed'), [$l->t('An administrator changed the administration rights of your account.')], $advice),
		};
	}

	/**
	 * @return list<string>
	 */
	private function settingSentences(AdminChangeFacts $facts, string $actor, IL10N $l): array {
		$label = $this->label($facts->setting ?? '', $l);
		$watch = $facts->watch === true;
		if ($facts->secret === true) {
			$sentences = [$watch
				? $l->t('The regular check of the security settings found that "%s" changed. Its value is secret, so it is neither stored nor shown.', [$label])
				: $l->t('%1$s changed "%2$s". Its value is secret, so it is neither stored nor shown.', [$actor, $label])];
		} else {
			$old = self::formatValue($facts->old, $l);
			$new = self::formatValue($facts->new, $l);
			$sentences = [$watch
				? $l->t('The regular check of the security settings found that "%1$s" changed from %2$s to %3$s.', [$label, $old, $new])
				: $l->t('%1$s changed "%2$s" from %3$s to %4$s.', [$actor, $label, $old, $new])];
		}
		if (($facts->setting ?? '') === WatchedSettings::systemKey('secret')) {
			$sentences[] = $l->t('Intrusion detection keys almost every fingerprint it keeps with this secret. Decoy app passwords created before no longer match their secret and are found by their login name only, so recreate them. Remembered browsers are forgotten, open lock links stop working, and the watched settings were recorded again without reporting each of them.');
		}
		if ($watch) {
			$sentences[] = $l->t('Nextcloud cannot tell who made this change: config.php and some settings can be changed without going through Nextcloud, for example by editing the file or with occ.');
		}
		return $sentences;
	}

	/**
	 * @return list<string>
	 */
	private function exemption(string $exempt, IL10N $l): array {
		return match ($exempt) {
			self::EXEMPT_OCC => [$l->t('It was done on the command line (occ), so it did not wait for the approval of a second administrator: whoever can run occ already controls the server. It is reported all the same.')],
			self::EXEMPT_CRON => [$l->t('It was done by a background job on the command line, so it did not wait for the approval of a second administrator: whoever can start it already controls the server. It is reported all the same.')],
			self::EXEMPT_DIRECTORY => [$l->t('The membership comes from a user directory such as LDAP, so it did not wait for the approval of a second administrator: Nextcloud cannot undo a membership that the directory sets. If it is wrong, change it in the directory.')],
			default => [],
		};
	}

	private function label(string $key, IL10N $l): string {
		return $key === '' ? $l->t('a setting') : $this->container->get(WatchedSettings::class)->label($key, $l);
	}

	/**
	 * The account a change was about. A deleted account's id is removed from
	 * stored detections, so this says so instead.
	 */
	private static function subject(Detection $detection, AdminChangeFacts $facts): string {
		return $detection->getUid() ?? $facts->common->targets[0] ?? '?';
	}

	public static function actorName(string $actor, IL10N $l): string {
		return match ($actor) {
			ActorResolver::OCC => $l->t('Someone on the command line (occ)'),
			ActorResolver::CRON => $l->t('A background job'),
			ActorResolver::UNKNOWN, '' => $l->t('Someone who was not logged in'),
			default => $actor,
		};
	}

	public static function formatValue(mixed $value, IL10N $l): string {
		if ($value === null) {
			return $l->t('not set');
		}
		if (is_bool($value)) {
			return $value ? $l->t('on') : $l->t('off');
		}
		if (is_array($value)) {
			return $value === [] ? $l->t('none') : '"' . implode(', ', array_map(static fn (mixed $v): string => is_scalar($v) ? (string)$v : '…', $value)) . '"';
		}
		if ($value === '') {
			return $l->t('empty');
		}
		return '"' . (is_scalar($value) ? (string)$value : '…') . '"';
	}
}
