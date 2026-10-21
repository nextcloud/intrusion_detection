<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\Detection;
use OCP\IL10N;

/**
 * What a detection is about in a few words: the check's own headline when
 * it names its detections ({@see IHeadlinesDetection}), otherwise the
 * check's name with the address or the account, e.g. "Credential stuffing
 * from 203.0.113.7". A detection of a check that no longer exists is named
 * by the check id.
 */
class DetectionHeadline {
	public function __construct(
		private readonly CheckRegistry $registry,
	) {
	}

	public function headline(Detection $detection, IL10N $l): string {
		$custom = $this->custom($detection, $l);
		if ($custom !== null) {
			return $custom;
		}
		$name = $this->checkName($detection->getCheckId(), $l);
		if ($detection->getIp() !== null) {
			return $l->t('%1$s from %2$s', [$name, $detection->getIp()]);
		}
		if ($detection->getUid() !== null) {
			return $l->t('%1$s: account %2$s', [$name, $detection->getUid()]);
		}
		return $name;
	}

	/**
	 * The headline the detection's check gives it, if it names its detections itself.
	 */
	public function custom(Detection $detection, IL10N $l): ?string {
		$checkId = $detection->getCheckId();
		if (!$this->registry->has($checkId)) {
			return null;
		}
		$check = $this->registry->check($this->registry->classOf($checkId));
		return $check instanceof IHeadlinesDetection ? $check->headline($detection, $l) : null;
	}

	public function checkName(string $checkId, IL10N $l): string {
		return $this->registry->has($checkId) ? $this->registry->get($checkId)->texts($l)->name : $checkId;
	}
}
