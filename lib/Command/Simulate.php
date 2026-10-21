<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Detection\Simulator;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Show what a check would report for an attack that just reaches its current
 * thresholds. Nothing is recorded, blocked or notified, and the address is
 * from the documentation range 198.51.100.0/24.
 */
class Simulate extends Base {
	public const TEST_ADDRESS = Simulator::TEST_ADDRESS;

	public function __construct(
		private readonly Simulator $simulator,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:simulate')
			->setDescription('Show what a check would report and do for a synthetic attack, without recording anything')
			->addArgument('check', InputArgument::REQUIRED, 'The check id, e.g. credential_stuffing');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$id = (string)$input->getArgument('check');
		if (!$this->simulator->canSimulate($id)) {
			$output->writeln('<error>This check does not exist or cannot be simulated.</error>');
			return self::INVALID;
		}
		$result = $this->simulator->simulate($id, $this->l);
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $result);
			return self::SUCCESS;
		}

		$output->writeln('<info>Simulation</info> of ' . $result['narrative']['title'] . ' with the test address ' . self::TEST_ADDRESS . '. Nothing is recorded, blocked or notified.');
		$output->writeln('');
		foreach ($result['narrative']['happened'] as $sentence) {
			$output->writeln($sentence);
		}
		$output->writeln('');
		if (!$result['runs']) {
			$output->writeln('<comment>The check is off, so in reality nothing would be recorded.</comment>');
		} elseif (!$result['acts']) {
			$output->writeln('<comment>The check runs as Observe' . ($result['modeReason'] !== null ? ' (' . $result['modeReason'] . ')' : '') . ', so it would only record this. With Protect it would:</comment>');
		} else {
			$output->writeln('<comment>Responses that would run:</comment>');
		}
		foreach ($result['responses'] as $response) {
			$output->writeln('- ' . $response['text']);
		}
		if ($result['responses'] === []) {
			$output->writeln('- ' . $this->l->t('Nothing is done; detections are only recorded.'));
		}
		return self::SUCCESS;
	}
}
