<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dashboard;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\LockdownOverview;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Dashboard\IAPIWidgetV2;
use OCP\Dashboard\IButtonWidget;
use OCP\Dashboard\IConditionalWidget;
use OCP\Dashboard\IIconWidget;
use OCP\Dashboard\IReloadableWidget;
use OCP\Dashboard\Model\WidgetButton;
use OCP\Dashboard\Model\WidgetItem;
use OCP\Dashboard\Model\WidgetItems;
use OCP\IGroupManager;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUserSession;

/**
 * The admin dashboard widget: a running lockdown, the status line, the last
 * 24 hours in numbers and the latest serious detections. Administrators only.
 *
 * @psalm-import-type IntrusionDetectionStatus from ResponseDefinitions
 */
class IntrusionWidget implements IAPIWidgetV2, IConditionalWidget, IIconWidget, IButtonWidget, IReloadableWidget {
	public const ID = 'intrusion_detection';
	/** Detections of this severity or above are listed */
	public const MIN_SEVERITY = Severity::High;
	public const MAX_DETECTIONS = 5;

	public function __construct(
		private readonly StatusService $status,
		private readonly DetectionMapper $detections,
		private readonly CheckNames $names,
		private readonly DateFormatter $dates,
		private readonly IUserSession $userSession,
		private readonly IGroupManager $groupManager,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getId(): string {
		return self::ID;
	}

	#[\Override]
	public function getTitle(): string {
		return $this->l->t('Intrusion detection');
	}

	#[\Override]
	public function getOrder(): int {
		return 30;
	}

	#[\Override]
	public function getIconClass(): string {
		return 'icon-intrusion-detection';
	}

	#[\Override]
	public function getIconUrl(): string {
		return $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg'));
	}

	#[\Override]
	public function getUrl(): ?string {
		return $this->pageUrl();
	}

	#[\Override]
	public function load(): void {
	}

	#[\Override]
	public function isEnabled(): bool {
		$user = $this->userSession->getUser();
		return $user !== null && $this->groupManager->isAdmin($user->getUID());
	}

	#[\Override]
	public function getReloadInterval(): int {
		return 300;
	}

	#[\Override]
	public function getWidgetButtons(string $userId): array {
		return [new WidgetButton(WidgetButton::TYPE_MORE, $this->pageUrl(), $this->l->t('Open intrusion detection'))];
	}

	#[\Override]
	public function getItemsV2(string $userId, ?string $since = null, int $limit = 7): WidgetItems {
		// The widget is registered for administrators only; checked again
		// because items can be requested through the dashboard API.
		if (!$this->groupManager->isAdmin($userId)) {
			return new WidgetItems();
		}
		$status = $this->status->status($this->l);
		$lockdown = $this->lockdownItem($status);
		$items = $lockdown === null ? [$this->statusItem($status)] : [$lockdown, $this->statusItem($status)];

		$detections = $this->detections->findList(new DetectionFilter(
			severities: array_values(array_map(
				static fn (Severity $s): string => $s->value,
				array_filter(Severity::cases(), static fn (Severity $s): bool => $s->atLeast(self::MIN_SEVERITY)),
			)),
			since: $this->timeFactory->getTime() - 30 * 86400,
			limit: max(0, min(self::MAX_DETECTIONS, $limit - count($items))),
		));
		foreach ($detections as $detection) {
			$items[] = $this->detectionItem($detection);
		}

		return new WidgetItems(
			$items,
			'',
			$detections === [] ? $this->l->t('No serious detections in the last 30 days.') : '',
		);
	}

	/**
	 * @param IntrusionDetectionStatus $status
	 */
	private function statusItem(array $status): WidgetItem {
		$last = $status['last24h'];
		$title = match ($status['state']) {
			StatusService::STATE_OFF => $this->l->t('Off: no checks run'),
			StatusService::STATE_LEARNING => $this->l->n('Learning mode, %n day left', 'Learning mode, %n days left', $status['learning']['daysLeft']),
			default => $this->l->t('Protecting'),
		};
		$subtitle = $status['state'] === StatusService::STATE_LEARNING
			? $this->l->n('Would have blocked %n address in 24 hours', 'Would have blocked %n addresses in 24 hours', $last['wouldHaveBlocked'])
				. ' · ' . $this->l->n('%n detection', '%n detections', $last['detections'])
			: $this->l->n('%n address blocked in 24 hours', '%n addresses blocked in 24 hours', $last['blockedAddresses'])
				. ' · ' . $this->l->n('%n detection', '%n detections', $last['detections']);
		$icon = $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg'));
		return new WidgetItem($title, $subtitle, $this->pageUrl(), $icon, 'status');
	}

	/**
	 * The running lockdown, on top: "Lockdown until 18:00", with who started it and why.
	 *
	 * @param IntrusionDetectionStatus $status
	 */
	private function lockdownItem(array $status): ?WidgetItem {
		$lockdown = $status['extensions'][LockdownOverview::KEY] ?? null;
		if (!is_array($lockdown) || ($lockdown['active'] ?? false) !== true) {
			return null;
		}
		$startedBy = (string)($lockdown['startedBy'] ?? '');
		$reason = (string)($lockdown['reason'] ?? '');
		$by = match ($startedBy) {
			Lockdown::ACTOR_AUTOMATIC => $this->l->t('Started automatically'),
			Lockdown::ACTOR_OCC => $this->l->t('Started with occ'),
			default => $this->l->t('Started by %s', [$startedBy]),
		};
		return new WidgetItem(
			$this->l->t('Lockdown until %s', [$this->dates->dateTime((int)($lockdown['until'] ?? 0))]),
			$reason === '' ? $by : $this->l->t('%1$s: "%2$s"', [$by, $reason]),
			$this->pageUrl(),
			$this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath('core', 'actions/password.svg')),
			'lockdown',
		);
	}

	private function detectionItem(Detection $detection): WidgetItem {
		$parts = array_filter([
			$detection->getIp(),
			$detection->getUid(),
			$this->dates->dateTime($detection->getLastSeenAt()),
		], static fn (?string $part): bool => $part !== null && $part !== '');
		$title = $this->names->name($detection->getCheckId(), $this->l);
		if (!$detection->isEnforced()) {
			$title = $this->l->t('%s (observed)', [$title]);
		}
		return new WidgetItem(
			$title,
			implode(' · ', $parts),
			$this->pageUrl() . '#detection-' . $detection->getId(),
			$this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath('core', 'actions/error.svg')),
			(string)$detection->getId(),
		);
	}

	private function pageUrl(): string {
		return $this->urlGenerator->linkToRouteAbsolute('settings.AdminSettings.index', ['section' => Application::APP_ID]);
	}
}
