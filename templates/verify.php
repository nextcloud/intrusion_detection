<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @var \OCP\IL10N $l */
/** @var array{mode: string, title: string, lead: string, logout_url: string, login_url: string, requesttoken: string, why?: ?string, error?: ?string, notice?: ?string, hasCode?: bool, attemptsLeft?: ?string, canResend?: bool, secondFactor?: bool, confirmAction?: string, resendAction?: string, secondFactorAction?: string, redirect_url?: string, reference?: ?string} $_ */
$mode = $_['mode'];
$error = $_['error'] ?? null;
$notice = $_['notice'] ?? null;
$described = $error !== null ? 'ids-verify-error' : null;
?>
<div class="guest-box ids-page">
	<?php if ($mode === 'code'): ?>
		<div class="ids-page__icon ids-page__icon--mail" aria-hidden="true"></div>
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
				<button class="primary ids-page__submit" type="submit"><?php p($l->t('Confirm and continue')); ?></button>
			</form>
		<?php endif; ?>

		<?php if (($_['canResend'] ?? false) || ($_['secondFactor'] ?? false)): ?>
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
			</div>
		<?php endif; ?>

		<p class="ids-page__warning">
			<?php p($l->t('If you did not just log in, someone knows your password. Do not enter the code anywhere; log out and change your password.')); ?>
		</p>

		<div class="ids-page__actions">
			<a href="<?php p($_['logout_url']); ?>"><?php p($l->t('Log out')); ?></a>
		</div>
	<?php elseif ($mode === 'refused'): ?>
		<?php if (($_['reference'] ?? null) !== null): ?>
			<p class="ids-page__hint">
				<?php p($l->t('Reference:')); ?> <span class="ids-page__reference"><?php p($_['reference']); ?></span>
			</p>
		<?php endif; ?>
		<div class="ids-page__actions">
			<a href="<?php p($_['login_url']); ?>"><?php p($l->t('Back to the login page')); ?></a>
		</div>
	<?php else: ?>
		<div class="ids-page__actions">
			<a href="<?php p($_['login_url']); ?>"><?php p($l->t('Log in again')); ?></a>
		</div>
	<?php endif; ?>
</div>
