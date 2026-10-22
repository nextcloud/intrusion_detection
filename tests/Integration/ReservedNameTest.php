<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class ReservedNameTest extends LoginFailureTestCase {
	private ReservedNames $names;

	protected function setUp(): void {
		parent::setUp();
		$this->names = Server::get(ReservedNames::class);
	}

	public function testNoNameTripsWhileNothingIsReserved(): void {
		$this->assertSame([], $this->names->list());
		$this->failLogin('198.51.100.7', 'admin-' . 'nobody');
		$this->assertSame([], $this->detectionsOf(ReservedName::ID));
	}

	public function testSuggestionsLeaveOutExistingAccounts(): void {
		$this->user('webmaster');
		$suggestions = $this->names->suggestions();
		$this->assertNotContains('webmaster', $suggestions);
		$this->assertContains('administrator', $suggestions);

		$this->names->add(['administrator'], 'test');
		$this->assertNotContains('administrator', $this->names->suggestions(), 'Reserved names are not suggested again');
	}

	public function testAnExistingAccountCannotBeReserved(): void {
		$this->user('support');
		try {
			$this->names->add(['Support'], 'test');
			$this->fail('An existing account was reserved');
		} catch (InvalidParamException $e) {
			$this->assertSame('existing_user', $e->reason);
		}
		$this->expectException(InvalidParamException::class);
		$this->settingsEditor()->setParam(ReservedName::ID, 'names', ['root', 'support']);
	}

	public function testAnAttemptWithAReservedNameBlocksTheSourceAndIsNotCounted(): void {
		$this->names->add(['administrator', 'root'], 'test');
		$this->failLogin('198.51.100.7', ' Root ');
		$detections = $this->detectionsOf(ReservedName::ID);
		$this->assertCount(1, $detections);
		$this->assertSame('root', $detections[0]->getExplanationData()['facts']['name']);
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys(['198.51.100.7'], time()));
		$this->assertSame(0, $this->rows('ids_attempts'), 'A reserved-name attempt is answered on its own');
	}

	public function testRepeatedAttemptsFromOneSourceAreOneDetection(): void {
		$this->settingsEditor()->setMode(ReservedName::ID, Mode::Observe);
		$this->names->add(['administrator'], 'test');
		for ($i = 0; $i < 4; $i++) {
			$this->failLogin('198.51.100.7', 'administrator');
		}
		$detections = $this->detectionsOf(ReservedName::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(4, $detections[0]->getHits());
		$this->assertSame(0, $this->rows('ids_bans'));
	}

	public function testANameThatBecameAnAccountIsSkipped(): void {
		$this->names->add(['guest'], 'test');
		$this->user('guest');
		$this->assertSame(['guest'], $this->names->collisions());
		$this->failLogin('198.51.100.7', 'guest');
		$this->assertSame([], $this->detectionsOf(ReservedName::ID));
		$this->assertSame(1, $this->rows('ids_attempts'), 'It counts as an ordinary failed login');
	}

	public function testOffSkipsTheCheck(): void {
		$this->names->add(['root'], 'test');
		$this->settingsEditor()->setMode(ReservedName::ID, Mode::Off);
		$this->failLogin('198.51.100.7', 'root');
		$this->assertSame(0, $this->rows('ids_detections'));
	}

	public function testRemovingANameStopsTheTrap(): void {
		$this->names->add(['root', 'test'], 'test');
		$this->assertSame(['test'], $this->names->remove(['ROOT'], 'test'));
		$this->failLogin('198.51.100.7', 'root');
		$this->assertSame([], $this->detectionsOf(ReservedName::ID));
	}
}
