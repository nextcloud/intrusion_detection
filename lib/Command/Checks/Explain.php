<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Checks;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Explain extends Base {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly CheckPresenter $presenter,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:checks:explain')
			->setDescription('Explain a check with its current settings')
			->addArgument('check', InputArgument::REQUIRED, 'The check id');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		try {
			$check = $this->registry->get((string)$input->getArgument('check'));
		} catch (InvalidParamException $e) {
			$output->writeln('<error>' . $e->describe($this->l) . '</error>');
			return self::INVALID;
		}
		$presented = $this->presenter->present($check, $this->l);
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $presented);
			return self::SUCCESS;
		}
		$texts = $presented['texts'];
		$output->writeln('<info>' . $texts['name'] . '</info> (' . $check->id . ')');
		$output->writeln('Mode: ' . $presented['mode']['configured'] . ', runs as ' . $presented['mode']['effective']
			. ($presented['mode']['reason'] !== null ? ' because of ' . $presented['mode']['reason'] : ''));
		$output->writeln('');
		$sections = [
			'What it detects' => $texts['detects'],
			'How it decides' => $presented['decides'],
			'What happens' => implode(' ', $presented['happens']),
			'When it may be wrong' => $texts['wrong'],
			'Cost' => $presented['cost']['text'],
			'Data' => $texts['data'],
		];
		foreach ($sections as $heading => $text) {
			$output->writeln('<comment>' . $heading . ':</comment> ' . $text);
		}
		if ($presented['params'] !== []) {
			$output->writeln('');
			$output->writeln('<comment>Settings:</comment>');
			foreach ($presented['params'] as $param) {
				$output->writeln(sprintf('  %s = %s (default %s%s)',
					$param['name'],
					json_encode($param['value']),
					json_encode($param['default']),
					$param['min'] !== null || $param['max'] !== null ? sprintf(', %s..%s', $param['min'] ?? '', $param['max'] ?? '') : '',
				));
			}
		}
		return self::SUCCESS;
	}
}
