<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Settings;

use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Settings\Admin;
use OCA\IntrusionDetection\Settings\AdminSection;
use OCP\AppFramework\Services\IInitialState;
use OCP\IL10N;
use OCP\IURLGenerator;
use Test\TestCase;

class AdminTest extends TestCase {
	public function testThePageComesWithItsStateAndMountPoint(): void {
		$status = $this->createMock(StatusService::class);
		$status->method('status')->willReturn(['state' => 'protecting']);
		$checks = $this->createMock(CheckList::class);
		$checks->method('all')->willReturn(['checks' => [], 'categories' => []]);
		$settings = $this->createMock(GlobalSettingsPresenter::class);
		$settings->method('present')->willReturn(['settings' => [], 'templates' => []]);
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('192.0.2.10'));
		$state = $this->createMock(IInitialState::class);
		$state->expects($this->once())->method('provideInitialState')->with('admin', $this->callback(
			static fn (array $data): bool => $data['status'] === ['state' => 'protecting']
				&& $data['checks'] === ['checks' => [], 'categories' => []]
				&& $data['ownAddress'] === '192.0.2.10'
				&& array_key_exists('docUrl', $data),
		));

		$admin = new Admin($status, $checks, $settings, $addresses, $state, $this->createMock(IURLGenerator::class), $this->createMock(IL10N::class));
		$response = $admin->getForm();

		$this->assertSame('settings-admin', $response->getTemplateName());
		$this->assertSame('intrusion_detection', $admin->getSection());
		$this->assertStringContainsString('id="intrusion_detection-admin-settings"', $response->render());
	}

	public function testTheSectionFollowsSecurity(): void {
		$urls = $this->createMock(IURLGenerator::class);
		$urls->expects($this->once())->method('imagePath')->with('intrusion_detection', 'app-dark.svg')->willReturn('/icon.svg');
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnArgument(0);
		$section = new AdminSection($urls, $l);
		$this->assertSame('intrusion_detection', $section->getID());
		$this->assertSame('Intrusion detection', $section->getName());
		$this->assertSame(11, $section->getPriority());
		$this->assertSame('/icon.svg', $section->getIcon());
	}
}
