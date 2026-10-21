<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Tells every administrator about changes that give or take administration
 * rights or weaken security: new administrators, group administrators,
 * accounts created by administrators, apps switched on or off, and changes
 * of the watched security settings. Optionally, a second administrator must
 * approve every new administrator.
 *
 * The detector is {@see AdminChangeDetector}; the events come from
 * {@see \OCA\IntrusionDetection\Listener\AdminChangeListener} and
 * {@see \OCA\IntrusionDetection\AdminChange\ConfigWatch}.
 */
final class AdminChange implements ICheck, IExplainsDetection, IHeadlinesDetection, IValidatesParams {
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
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Admin change alerts'),
				shortName: $l->t('Admin change'),
				summary: $l->t('Someone got administrator rights, an app was switched on or off, or a security setting changed.'),
				detects: $l->t('An intruder who gets into an administrator account usually makes themselves at home: they give a second account administrator rights, switch on an app, or weaken a security setting so that the next step is easier. This check tells every administrator about such changes, including the one who made them. If that account was taken over, its owner still learns what was done in their name.'),
				decides: $l->t('Fires on every change: an account added to the admin group or to a group with delegated administration settings, a group administrator appointed, an account created by an administrator, an app switched on or off, and every change of the watched security settings. Changes in config.php are found by a check every 5 minutes. A second administrator must approve new administrators: {admin_change_require_approval}. A request for approval expires after %s.', [TextRenderer::duration(ApprovalService::TTL, $l)]),
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

	#[\Override]
	public function headline(Detection $detection, IL10N $l): ?string {
		$facts = DetectionFacts::of($detection);
		$subject = self::subject($detection);
		return match ($facts->string('kind')) {
			self::KIND_ADMIN_GRANTED => $facts->list('delegated') !== []
				? $l->t('%1$s got administration rights through the group "%2$s"', [$subject, $facts->string('group')])
				: $l->t('%s was made an administrator', [$subject]),
			self::KIND_GRANT_REQUESTED => $l->t('Approval needed: %s to become an administrator', [$subject]),
			self::KIND_ADMIN_REMOVED => $facts->list('delegated') !== []
				? $l->t('%1$s left the group "%2$s", which has administration rights', [$subject, $facts->string('group')])
				: $l->t('%s is no longer an administrator', [$subject]),
			self::KIND_SUBADMIN_GRANTED => $l->t('%1$s was made a group administrator of "%2$s"', [$subject, $facts->string('group')]),
			self::KIND_USER_CREATED => $l->t('The account %s was created', [$subject]),
			self::KIND_APP_ENABLED => $l->t('The app "%s" was switched on', [$facts->string('app')]),
			self::KIND_APP_DISABLED => $l->t('The app "%s" was switched off', [$facts->string('app')]),
			self::KIND_SETTING_CHANGED => $l->t('Security setting changed: %s', [$this->label($facts->string('setting'), $l)]),
			default => null,
		};
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$actor = self::actorName($facts->string('actor', ActorResolver::UNKNOWN), $l);
		$subject = self::subject($detection);
		$group = $facts->string('group');
		$delegated = $facts->list('delegated');
		$sentences = [];

		switch ($facts->string('kind')) {
			case self::KIND_ADMIN_GRANTED:
				$sentences[] = $delegated !== []
					? $l->t('%1$s added %2$s to the group "%3$s", which has these administration settings: %4$s.', [$actor, $subject, $group, implode(', ', $delegated)])
					: $l->t('%1$s made %2$s an administrator.', [$actor, $subject]);
				if ($facts->string('approved_by') !== '') {
					$sentences[] = $l->t('%1$s asked for it, and %2$s approved it.', [self::actorName($facts->string('requested_by', ActorResolver::UNKNOWN), $l), $facts->string('approved_by')]);
				}
				$sentences = array_merge($sentences, $this->exemption($facts->string('exempt'), $l));
				break;
			case self::KIND_GRANT_REQUESTED:
				$sentences[] = $l->t('%1$s tried to make %2$s an administrator.', [$actor, $subject]);
				if ($facts->bool('revert_failed')) {
					$sentences[] = $l->t('A second administrator must approve new administrators, but Nextcloud could not take %s out of the admin group again. Check the members of the admin group now.', [$subject]);
				} else {
					$sentences[] = $l->t('A second administrator must approve new administrators, so %s was taken out of the admin group again at once.', [$subject]);
					$sentences[] = $facts->has('approval')
						? $l->t('The request waits for the approval of another administrator until %s. Neither the one who asked nor the account itself can approve it.', [$this->dates->dateTime($facts->int('expires_at'))])
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
				$groups = $facts->list('groups');
				$sentences[] = $groups === []
					? $l->t('%1$s switched on the app "%2$s" for everyone.', [$actor, $facts->string('app')])
					: $l->t('%1$s switched on the app "%2$s" for the groups %3$s.', [$actor, $facts->string('app'), implode(', ', $groups)]);
				break;
			case self::KIND_APP_DISABLED:
				$sentences[] = $l->t('%1$s switched off the app "%2$s".', [$actor, $facts->string('app')]);
				if ($facts->string('app') === Application::APP_ID) {
					$sentences[] = $l->t('This switches off intrusion detection itself: nothing is watched or blocked any more until it is switched on again.');
				}
				break;
			case self::KIND_SETTING_CHANGED:
				$sentences = $this->settingSentences($facts, $actor, $l);
				break;
			default:
				$sentences[] = $l->t('An administration setting was changed.');
		}

		$ip = $facts->string('actor_ip');
		if ($ip !== '') {
			$sentences[] = $l->t('The change came from the address %s.', [$ip]);
		}
		$sentences[] = $l->t('It happened at %s.', [$this->dates->dateTime($detection->getCreatedAt())]);
		return $sentences;
	}

	/**
	 * @return list<string>
	 */
	private function settingSentences(DetectionFacts $facts, string $actor, IL10N $l): array {
		$label = $this->label($facts->string('setting'), $l);
		$watch = $facts->bool('watch');
		if ($facts->bool('secret')) {
			$sentences = [$watch
				? $l->t('The regular check of the security settings found that "%s" changed. Its value is secret, so it is neither stored nor shown.', [$label])
				: $l->t('%1$s changed "%2$s". Its value is secret, so it is neither stored nor shown.', [$actor, $label])];
		} else {
			$old = self::formatValue($facts->value('old'), $l);
			$new = self::formatValue($facts->value('new'), $l);
			$sentences = [$watch
				? $l->t('The regular check of the security settings found that "%1$s" changed from %2$s to %3$s.', [$label, $old, $new])
				: $l->t('%1$s changed "%2$s" from %3$s to %4$s.', [$actor, $label, $old, $new])];
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
	private static function subject(Detection $detection): string {
		$targets = DetectionFacts::of($detection)->list('targets');
		return $detection->getUid() ?? $targets[0] ?? '?';
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
