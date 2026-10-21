<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
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
	public const TEST_ADDRESS = '198.51.100.23';

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly DetectionService $detections,
		private readonly NarrativeBuilder $narratives,
		private readonly ITimeFactory $timeFactory,
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
		try {
			$definition = $this->registry->get($id);
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}
		$check = $this->registry->check($this->registry->classOf($id));
		if (!$definition->simulatable || !$check instanceof ISimulatable) {
			$output->writeln('<error>This check cannot be simulated.</error>');
			return self::INVALID;
		}

		$mode = $this->settings->modeState($id);
		$draft = $check->simulate(SourceKey::fromIp(self::TEST_ADDRESS), $this->timeFactory->getTime(), $this->settings->params($id));
		$detection = $this->detections->preview($draft, $mode);
		$responses = $this->settings->responses($id);
		if ($check instanceof ISelectsResponses) {
			$responses = $check->responsesFor($draft, $responses, $this->settings->params($id));
		}
		usort($responses, static fn (ResponseType $a, ResponseType $b): int => $a->order() <=> $b->order());
		$detection->setActionList(array_map(static fn (ResponseType $r): array => ['type' => $r->value, 'enforced' => false], $responses));
		$narrative = $this->narratives->build($detection, $this->l);

		$result = [
			'check' => $id,
			'mode' => $mode->effective->value,
			'modeReason' => $mode->reason,
			'narrative' => $narrative->toArray(),
			'responses' => array_map(static fn (ResponseType $r): string => $r->value, $responses),
		];
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $result);
			return self::SUCCESS;
		}

		$output->writeln('<info>Simulation</info> of ' . $narrative->title . ' with the test address ' . self::TEST_ADDRESS . '. Nothing is recorded, blocked or notified.');
		$output->writeln('');
		foreach ($narrative->happened as $sentence) {
			$output->writeln($sentence);
		}
		$output->writeln('');
		if (!$mode->runs()) {
			$output->writeln('<comment>The check is off, so in reality nothing would be recorded.</comment>');
		} elseif (!$mode->acts()) {
			$output->writeln('<comment>The check runs as Observe' . ($mode->reason !== null ? ' (' . $mode->reason . ')' : '') . ', so it would only record this. With Protect it would:</comment>');
		} else {
			$output->writeln('<comment>Responses that would run:</comment>');
		}
		foreach ($responses as $response) {
			$output->writeln('- ' . $response->describe($this->l));
		}
		if ($responses === []) {
			$output->writeln('- ' . $this->l->t('Nothing is done; detections are only recorded.'));
		}
		return self::SUCCESS;
	}
}
