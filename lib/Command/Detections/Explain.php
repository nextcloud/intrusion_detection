<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Detections;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Explain extends Base {
	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly NarrativeBuilder $narratives,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:detections:explain')
			->setDescription('Explain why a detection happened and what Nextcloud did')
			->addArgument('id', InputArgument::REQUIRED, 'The detection id');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		try {
			$detection = $this->mapper->findById((string)$input->getArgument('id'));
		} catch (DoesNotExistException) {
			$output->writeln('<error>There is no such detection.</error>');
			return self::FAILURE;
		}
		$narrative = $this->narratives->build($detection, $this->l);
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $narrative->toArray() + ['detection' => $detection->jsonSerialize()]);
			return self::SUCCESS;
		}
		$output->writeln($narrative->toText($detection->isEnforced() ? 'What Nextcloud did:' : 'What Nextcloud would have done:'));
		return self::SUCCESS;
	}
}
