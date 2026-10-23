<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Command\Payload;

use OC\Core\Command\Base;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadTester;
use OCP\IL10N;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Shows what the injection probe check makes of a URL or a value: the
 * normalised form, the decoded base64, the matched signatures with their
 * weights, and whether it would fire. Nothing is sent or recorded.
 */
class Test extends Base {
	public function __construct(
		private readonly PayloadTester $tester,
		private readonly IL10N $l,
	) {
		parent::__construct();
	}

	#[\Override]
	protected function configure(): void {
		parent::configure();
		$this->setName('intrusion:payload:test')
			->setDescription('Show how the injection probe check sees a URL or a parameter value')
			->addArgument('url-or-value', InputArgument::REQUIRED, 'A URL (https://… or a path starting with /) or a single parameter value');
	}

	#[\Override]
	protected function execute(InputInterface $input, OutputInterface $output): int {
		$result = $this->tester->test((string)$input->getArgument('url-or-value'), $this->l);
		if ($input->getOption('output') !== self::OUTPUT_FORMAT_PLAIN) {
			$this->writeArrayInOutputFormat($input, $output, $result);
			return self::SUCCESS;
		}

		$output->writeln(sprintf('Signatures version %d, minimum weight %d, at most %d bytes per request.', $result['signaturesVersion'], $result['minWeight'], $result['maxBytes']));
		$output->writeln($result['prefilter']
			? 'Pre-filter: suspicious, so the request is inspected in full.'
			: 'Pre-filter: nothing suspicious; a request like this is not inspected further.');
		if ($result['pathExcluded']) {
			$output->writeln('The path is a file path and is not inspected.');
		}
		foreach ($result['values'] as $value) {
			$output->writeln('');
			$output->writeln('<info>' . $this->label($value) . '</info>');
			if ($value['skipped'] !== null) {
				$output->writeln('  not inspected: ' . match ($value['skipped']) {
					'secret' => 'password, secret or token field',
					'free_text' => 'excluded free-text field',
					default => 'the byte limit was reached',
				});
				continue;
			}
			if ($value['truncated']) {
				$output->writeln('  (cut at the byte limit)');
			}
			foreach ($value['forms'] as $form) {
				$heading = match ($form['encoding']) {
					'base64' => 'decoded from base64',
					'base64_twice' => 'decoded from base64 twice',
					default => 'normalised',
				};
				$output->writeln('  ' . $heading . ': ' . $form['text']);
				foreach ($form['matches'] as $match) {
					$output->writeln(sprintf('    %s (weight %d): %s', $match['id'], $match['weight'], $match['description']));
				}
				if ($form['matches'] !== []) {
					$output->writeln(sprintf('    total weight %d of %d', $form['weight'], $result['minWeight']));
				}
			}
			$output->writeln($value['fires'] ? '  <comment>fires</comment>' : '  does not fire');
		}
		$output->writeln('');
		if ($result['fires']) {
			$output->writeln(sprintf(
				'<comment>Would fire.</comment> Visitors who are not logged in: %s. Logged-in users: %s.',
				$result['modes']['anonymous'],
				$result['modes']['authenticated'],
			));
		} else {
			$output->writeln('Would not fire.');
		}
		return self::SUCCESS;
	}

	/**
	 * @param array<string, mixed> $value
	 */
	private function label(array $value): string {
		return match ($value['location']) {
			'path' => 'path',
			'form' => $value['name'] === '' ? 'value' : 'form field ' . $value['name'],
			default => 'query parameter ' . $value['name'],
		};
	}
}
