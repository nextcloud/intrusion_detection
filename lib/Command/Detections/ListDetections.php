<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Detections;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCP\AppFramework\Utility\ITimeFactory;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ListDetections extends Base {
	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:detections:list')
			->setDescription('List recent detections')
			->addOption('check', 'c', InputOption::VALUE_REQUIRED, 'Only this check')
			->addOption('since', 's', InputOption::VALUE_REQUIRED, 'Only the last ..., e.g. 24h or 7d')
			->addOption('user', 'u', InputOption::VALUE_REQUIRED, 'Only detections about this account')
			->addOption('observed', null, InputOption::VALUE_NONE, 'Only detections that were observed, not acted on')
			->addOption('limit', 'l', InputOption::VALUE_REQUIRED, 'At most this many', '50');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$since = null;
		if (is_string($input->getOption('since'))) {
			$since = $this->timeFactory->getTime() - ParamDefinition::parseDuration((string)$input->getOption('since'));
		}
		$filter = new DetectionFilter(
			checkIds: is_string($input->getOption('check')) ? [(string)$input->getOption('check')] : [],
			uid: is_string($input->getOption('user')) ? (string)$input->getOption('user') : null,
			enforced: $input->getOption('observed') ? false : null,
			since: $since,
			limit: max(1, min(1000, (int)$input->getOption('limit'))),
		);
		$detections = $this->mapper->findList($filter);
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, array_map(static fn (Detection $d): array => $d->jsonSerialize(), $detections));
			return self::SUCCESS;
		}
		if ($detections === []) {
			$output->writeln('No detections.');
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Id', 'When', 'Check', 'Severity', 'Address', 'Account', 'Hits', 'Acted']);
		foreach ($detections as $d) {
			$table->addRow([$d->getId(), date('Y-m-d H:i', $d->getCreatedAt()), $d->getCheckId(), $d->getSeverity(), $d->getIp() ?? '', $d->getUid() ?? '', $d->getHits(), $d->isEnforced() ? 'yes' : 'would have']);
		}
		$table->render();
		return self::SUCCESS;
	}
}
