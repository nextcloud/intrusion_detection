<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Blocklists;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

class ListBlocklists extends Base {
	public function __construct(
		private readonly BlocklistOverview $overview,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:blocklists:list')
			->setDescription('List the blocklists and network attribute lists, with their sync status')
			->addOption('matches', 'm', InputOption::VALUE_NONE, 'Also show the matches of the last 14 days');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$lists = $this->overview->lists();
		$matches = $input->getOption('matches') ? $this->overview->matches() : null;
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $matches === null ? $lists : ['lists' => $lists, 'matches' => $matches]);
			return self::SUCCESS;
		}
		$table = new Table($output);
		$table->setHeaders(['Id', 'Purpose', 'Mode', 'On', 'Ranges', 'Last success', 'Last error', 'Reference']);
		foreach ($lists as $list) {
			$table->addRow([
				$list['id'],
				$list['purpose'],
				$list['mode'] ?? '-',
				$list['enabled'] ? 'yes' : 'no',
				$list['version'] === null ? '-' : (string)$list['ranges'],
				$list['lastSuccessAt'] === null ? 'never' : date('Y-m-d H:i', $list['lastSuccessAt']),
				$list['lastError'] === null ? '' : $list['lastError'] . ($list['stale'] ? ' (stale)' : ''),
				$list['reference'] ?? '',
			]);
		}
		$table->render();
		if ($matches !== null) {
			if (!$this->overview->countsMatches()) {
				$output->writeln('Matches are not counted on this server, because it has no memory cache.');
			}
			foreach ($matches as $id => $days) {
				foreach ($days as $day) {
					$output->writeln(sprintf('%s %s: %d match(es), last: %s', $day['day'], $id, $day['matches'], implode(', ', $day['sample'])));
				}
			}
		}
		return self::SUCCESS;
	}
}
