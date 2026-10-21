<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * In the last 7 days the safety valve kept an address from being blocked,
 * because many people log in from it. Right for an office network; for a
 * reverse proxy it means attacks through it cannot be blocked.
 */
class SharedAddressCheck extends ProblemCheck {
	public const DAYS = 7;
	private const SHOWN = 3;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly DetectionMapper $detections,
		private readonly ITimeFactory $timeFactory,
		private readonly IURLGenerator $urlGenerator,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: shared addresses');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('No block was held back in the last 7 days because many people use an address.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$filter = new DetectionFilter(checkIds: [SharedAddress::ID], since: $this->timeFactory->getTime() - self::DAYS * 86400, limit: 20);
		$count = $this->detections->count($filter);
		if ($count === 0) {
			return null;
		}
		$addresses = [];
		foreach ($this->detections->findList($filter) as $detection) {
			if ($detection->getIp() !== null) {
				$addresses[$detection->getIp()] = true;
			}
		}
		$shown = implode(', ', array_slice(array_keys($addresses), 0, self::SHOWN));
		return new Finding(
			'shared_address',
			Finding::LEVEL_WARNING,
			$l->t('Blocks were held back for shared addresses'),
			$l->n(
				'In the last %1$s days, an address was not blocked %n time because many people log in from it: %2$s. That is right for an office network. If it is your reverse proxy, attackers behind it cannot be blocked.',
				'In the last %1$s days, addresses were not blocked %n times because many people log in from them: %2$s. That is right for an office network. If one is your reverse proxy, attackers behind it cannot be blocked.',
				$count,
				[(string)self::DAYS, $shown],
			),
			$l->t('If the address is your reverse proxy, add it to "trusted_proxies" in config.php. If it is an office network, nothing needs to be done.'),
			$this->urlGenerator->linkToDocs('admin-reverse-proxy'),
			$l->t('Reverse proxy documentation'),
		);
	}
}
