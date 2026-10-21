<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dashboard;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
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
 * The admin dashboard widget: the status line, the last 24 hours in numbers
 * and the latest serious detections. Administrators only.
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
		// With the id of the newest detection the client has, only newer detections are new items.
		$afterId = $since !== null && ctype_digit($since) ? (int)$since : null;
		$items = $afterId === null ? [$this->statusItem($this->status->status($this->l))] : [];

		$detections = $this->detections->findList(new DetectionFilter(
			severities: array_values(array_map(
				static fn (Severity $s): string => $s->value,
				array_filter(Severity::cases(), static fn (Severity $s): bool => $s->atLeast(self::MIN_SEVERITY)),
			)),
			since: $this->timeFactory->getTime() - 30 * 86400,
			limit: max(0, min(self::MAX_DETECTIONS, $afterId === null ? $limit - 1 : $limit)),
			afterId: $afterId,
		));
		foreach ($detections as $detection) {
			$items[] = $this->detectionItem($detection);
		}

		return new WidgetItems(
			$items,
			'',
			$detections === [] && $afterId === null ? $this->l->t('No serious detections in the last 30 days.') : '',
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
		return new WidgetItem($title, $subtitle, $this->pageUrl(), $this->itemIcon('widget-status.svg'), 'status');
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
			$this->itemIcon('widget-detection.svg'),
			(string)$detection->getId(),
		);
	}

	/**
	 * An icon for an item. The dashboard shows it as an image, so it cannot
	 * follow the theme: it is drawn in the Nextcloud blue, which reads on a
	 * light and on a dark background.
	 */
	private function itemIcon(string $image): string {
		return $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, $image));
	}

	private function pageUrl(): string {
		return $this->urlGenerator->linkToRouteAbsolute('settings.AdminSettings.index', ['section' => Application::APP_ID]);
	}
}
