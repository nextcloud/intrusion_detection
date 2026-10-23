<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @var \OCP\IL10N $l */
/** @var array{mode: string, title: string, lead: string, logout_url: string, login_url: string, requesttoken: string, why?: ?string, error?: ?string, notice?: ?string, hasCode?: bool, attemptsLeft?: ?string, canResend?: bool, secondFactor?: bool, askAdmin?: bool, waiting?: bool, canRemember?: bool, rememberHint?: string, confirmAction?: string, resendAction?: string, secondFactorAction?: string, askAdminAction?: string, waitingUrl?: string, redirect_url?: string, reference?: ?string, expires?: string, codeUrl?: string, statusUrl?: string, pollInterval?: int, continueAction?: string, cancelAction?: string, endAction?: string} $_ */
$mode = $_['mode'];
$error = $_['error'] ?? null;
$notice = $_['notice'] ?? null;
$described = $error !== null ? 'ids-verify-error' : null;
?>
<div class="guest-box ids-page">
	<?php if ($mode === 'code'): ?>
		<div class="ids-page__icon ids-page__icon--mail" aria-hidden="true"></div>
	<?php elseif ($mode === 'waiting'): ?>
		<div class="ids-page__icon ids-page__icon--waiting" aria-hidden="true"></div>
	<?php else: ?>
		<div class="ids-page__icon ids-page__icon--blocked" aria-hidden="true"></div>
	<?php endif; ?>
	<h2 class="ids-page__title"><?php p($_['title']); ?></h2>
	<p class="ids-page__lead"><?php p($_['lead']); ?></p>

	<?php if ($mode === 'code'): ?>
		<?php if (($_['why'] ?? null) !== null): ?>
			<p class="ids-page__hint"><?php p($_['why']); ?></p>
		<?php endif; ?>

		<?php if ($error !== null): ?>
			<p class="ids-page__error" id="ids-verify-error" role="alert"><?php p($error); ?></p>
		<?php elseif ($notice !== null): ?>
			<p class="ids-page__notice" role="status"><?php p($notice); ?></p>
		<?php endif; ?>

		<?php if ($_['hasCode'] ?? false): ?>
			<form class="ids-page__form" method="post" action="<?php p($_['confirmAction'] ?? ''); ?>">
				<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
				<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url'] ?? ''); ?>">
				<label class="ids-page__label" for="ids-verify-code"><?php p($l->t('Code from the email')); ?></label>
				<input class="ids-page__input ids-page__code" id="ids-verify-code" type="text" name="code"
					inputmode="numeric" autocomplete="one-time-code" maxlength="9" required autofocus
					spellcheck="false" autocapitalize="off"
					<?php if ($described !== null): ?>aria-describedby="<?php p($described); ?>" aria-invalid="true"<?php endif; ?>>
				<?php if ($error === null && ($_['attemptsLeft'] ?? null) !== null): ?>
					<p class="ids-page__meta"><?php p($_['attemptsLeft']); ?></p>
				<?php endif; ?>
				<?php if ($_['canRemember'] ?? false): ?>
					<div class="ids-page__remember">
						<input id="ids-verify-remember" type="checkbox" name="remember" value="1" aria-describedby="ids-verify-remember-hint">
						<label for="ids-verify-remember"><?php p($l->t('Remember this device')); ?></label>
						<p class="ids-page__meta" id="ids-verify-remember-hint"><?php p($_['rememberHint'] ?? ''); ?></p>
					</div>
				<?php endif; ?>
				<button class="primary ids-page__submit" type="submit"><?php p($l->t('Confirm and continue')); ?></button>
			</form>
		<?php endif; ?>

		<?php if (($_['canResend'] ?? false) || ($_['secondFactor'] ?? false) || ($_['askAdmin'] ?? false)): ?>
			<div class="ids-page__alternatives">
				<?php if ($_['canResend'] ?? false): ?>
					<form method="post" action="<?php p($_['resendAction'] ?? ''); ?>">
						<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
						<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url'] ?? ''); ?>">
						<button class="ids-page__secondary" type="submit"><?php p($l->t('Send a new code')); ?></button>
					</form>
				<?php endif; ?>
				<?php if ($_['secondFactor'] ?? false): ?>
					<form method="post" action="<?php p($_['secondFactorAction'] ?? ''); ?>">
						<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
						<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url'] ?? ''); ?>">
						<button class="ids-page__secondary" type="submit"><?php p($l->t('Confirm with your second factor')); ?></button>
					</form>
				<?php endif; ?>
				<?php if (($_['askAdmin'] ?? false) && ($_['waiting'] ?? false)): ?>
					<a class="ids-page__secondary ids-page__link-button" href="<?php p($_['waitingUrl'] ?? ''); ?>"><?php p($l->t('Back to waiting for an administrator')); ?></a>
				<?php elseif ($_['askAdmin'] ?? false): ?>
					<form method="post" action="<?php p($_['askAdminAction'] ?? ''); ?>">
						<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
						<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url'] ?? ''); ?>">
						<button class="ids-page__secondary" type="submit"><?php p($l->t('Ask an administrator')); ?></button>
					</form>
				<?php endif; ?>
			</div>
		<?php endif; ?>

		<p class="ids-page__warning">
			<?php p($l->t('If you did not just log in, someone knows your password. Do not enter the code anywhere; log out and change your password.')); ?>
		</p>

		<div class="ids-page__actions">
			<a href="<?php p($_['logout_url']); ?>"><?php p($l->t('Log out')); ?></a>
		</div>
	<?php elseif ($mode === 'waiting'): ?>
		<?php if (($_['why'] ?? null) !== null): ?>
			<p class="ids-page__hint"><?php p($_['why']); ?></p>
		<?php endif; ?>

		<div class="ids-page__waiting" data-ids-poll="<?php p($_['statusUrl'] ?? ''); ?>" data-ids-poll-interval="<?php p((string)($_['pollInterval'] ?? 10)); ?>" data-ids-poll-form="ids-approval-continue">
			<span class="ids-page__spinner" aria-hidden="true"></span>
			<p class="ids-page__waiting-text" role="status" aria-live="polite" data-ids-poll-status
				data-ids-text-pending="<?php p($l->t('Waiting for an administrator…')); ?>"
				data-ids-text-decided="<?php p($l->t('An administrator decided. Continuing…')); ?>"
				data-ids-text-offline="<?php p($l->t('Cannot reach the server. Trying again…')); ?>"><?php p($notice ?? $l->t('Waiting for an administrator…')); ?></p>
		</div>
		<p class="ids-page__meta"><?php p($_['expires'] ?? ''); ?></p>

		<form class="ids-page__form" id="ids-approval-continue" method="post" action="<?php p($_['continueAction'] ?? ''); ?>">
			<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
			<input type="hidden" name="redirect_url" value="<?php p($_['redirect_url'] ?? ''); ?>">
			<?php if ($_['canRemember'] ?? false): ?>
				<div class="ids-page__remember">
					<input id="ids-verify-remember" type="checkbox" name="remember" value="1" aria-describedby="ids-verify-remember-hint">
					<label for="ids-verify-remember"><?php p($l->t('Remember this device')); ?></label>
					<p class="ids-page__meta" id="ids-verify-remember-hint"><?php p($_['rememberHint'] ?? ''); ?></p>
				</div>
			<?php endif; ?>
			<button class="ids-page__secondary ids-page__check" type="submit"><?php p($l->t('Check now')); ?></button>
		</form>

		<div class="ids-page__alternatives">
			<?php if ($_['hasCode'] ?? false): ?>
				<a class="ids-page__secondary ids-page__link-button" href="<?php p($_['codeUrl'] ?? ''); ?>"><?php p($l->t('Use the code from the email instead')); ?></a>
			<?php endif; ?>
			<form method="post" action="<?php p($_['cancelAction'] ?? ''); ?>">
				<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
				<button class="ids-page__secondary" type="submit"><?php p($l->t('Cancel this login')); ?></button>
			</form>
		</div>

		<p class="ids-page__warning">
			<?php p($l->t('If you did not just log in, someone knows your password. Cancel this login, then change your password.')); ?>
		</p>
	<?php elseif ($mode === 'refused'): ?>
		<?php if (($_['why'] ?? null) !== null): ?>
			<p class="ids-page__hint"><?php p($_['why']); ?></p>
		<?php endif; ?>
		<?php if (($_['reference'] ?? null) !== null): ?>
			<p class="ids-page__hint">
				<?php p($l->t('Give your administrator this reference, so that they can see what happened:')); ?> <span class="ids-page__reference"><?php p($_['reference']); ?></span>
			</p>
		<?php else: ?>
			<p class="ids-page__hint"><?php p($l->t('Please contact your administrator.')); ?></p>
		<?php endif; ?>
		<form class="ids-page__actions" method="post" action="<?php p($_['endAction'] ?? ''); ?>">
			<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
			<button class="ids-page__secondary" type="submit"><?php p($l->t('Back to the login page')); ?></button>
		</form>
	<?php else: ?>
		<div class="ids-page__actions">
			<a href="<?php p($_['login_url']); ?>"><?php p($l->t('Log in again')); ?></a>
		</div>
	<?php endif; ?>
</div>
