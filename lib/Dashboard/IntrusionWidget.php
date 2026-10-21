<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dashboard;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\ConfirmationOverview;
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
 * The admin dashboard widget: the logins that wait for this administrator's
 * approval, the status line, the last 24 hours in numbers and the latest
 * serious detections. Administrators only.
 *
 * @psalm-import-type IntrusionDetectionStatus from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLoginApproval from ResponseDefinitions
 */
class IntrusionWidget implements IAPIWidgetV2, IConditionalWidget, IIconWidget, IButtonWidget, IReloadableWidget {
	public const ID = 'intrusion_detection';
	/** Detections of this severity or above are listed */
	public const MIN_SEVERITY = Severity::High;

	public function __construct(
		private readonly StatusService $status,
		private readonly ConfirmationOverview $confirmation,
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
		$items = [];
		if ($afterId === null) {
			// Waiting logins are read live: a user waits on the other side.
			foreach ($this->confirmation->pendingLogins($userId) as $approval) {
				if ($approval['canDecide']) {
					$items[] = $this->approvalItem($approval);
				}
			}
			$items[] = $this->statusItem($this->status->status($this->l));
		}

		$detections = $this->detections->findList(new DetectionFilter(
			severities: array_values(array_map(
				static fn (Severity $s): string => $s->value,
				array_filter(Severity::cases(), static fn (Severity $s): bool => $s->atLeast(self::MIN_SEVERITY)),
			)),
			since: $this->timeFactory->getTime() - 30 * 86400,
			// A full list makes the dashboard show the "Open intrusion detection" link.
			limit: max(0, $limit - count($items)),
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

	/**
	 * @param IntrusionDetectionLoginApproval $approval
	 */
	private function approvalItem(array $approval): WidgetItem {
		return new WidgetItem(
			$this->l->t('%s waits for your approval', [$approval['displayName']]),
			$approval['ip'] === null ? $this->l->t('Login') : $this->l->t('Login from %s', [$approval['ip']]),
			$this->pageUrl() . '#overview-attention',
			$this->itemIcon('widget-approval.svg'),
			'approval-' . $approval['id'],
		);
	}

	/**
	 * "Failed 2nd factor · alice" over "4 minutes ago · 198.51.100.7": the
	 * account, or the address when there is none, fits next to the short name.
	 */
	private function detectionItem(Detection $detection): WidgetItem {
		$uid = $detection->getUid() ?? '';
		$ip = $detection->getIp() ?? '';
		$subject = $uid !== '' ? $uid : $ip;
		$title = $this->names->shortName($detection->getCheckId(), $this->l);
		if ($subject !== '') {
			$title .= ' · ' . $subject;
		}
		$parts = array_filter([
			$this->dates->ago($detection->getLastSeenAt(), $this->timeFactory->getTime()),
			$uid !== '' ? $ip : '',
			$detection->isEnforced() ? '' : $this->l->t('observed'),
		], static fn (string $part): bool => $part !== '');
		return new WidgetItem(
			$title,
			implode(' · ', $parts),
			$this->pageUrl() . '#detection-' . $detection->getId(),
			$this->itemIcon(match (Severity::tryFrom($detection->getSeverity())) {
				Severity::Critical => 'widget-detection-critical.svg',
				Severity::High => 'widget-detection-high.svg',
				default => 'widget-detection.svg',
			}),
			(string)$detection->getId(),
		);
	}

	/**
	 * An icon for an item. The dashboard shows it as an image, so it cannot
	 * follow the theme: it is drawn in fixed colours that read on a light and
	 * on a dark background, the Nextcloud blue, and orange and red for high
	 * and critical detections.
	 */
	private function itemIcon(string $image): string {
		return $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, $image));
	}

	private function pageUrl(): string {
		return $this->urlGenerator->linkToRouteAbsolute('settings.AdminSettings.index', ['section' => Application::APP_ID]);
	}
}
