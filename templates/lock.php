<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/** @var \OCP\IL10N $l */
/** @var array{mode: string, login_url: string, requesttoken: string, action?: string, token?: string, nonce?: string, sentTo?: string, error?: ?string} $_ */
$mode = $_['mode'];
$error = $_['error'] ?? null;
?>
<div class="guest-box ids-page ids-lock">
	<?php if ($mode === 'confirm'): ?>
		<div class="ids-page__icon ids-page__icon--blocked" aria-hidden="true"></div>
		<h2 class="ids-page__title"><?php p($l->t('Lock this account?')); ?></h2>
		<p class="ids-page__lead">
			<?php p($l->t('Nextcloud sent this link to %s because the email address of an account was changed, together with other security settings.', [$_['sentTo'] ?? ''])); ?>
		</p>
		<p class="ids-page__hint"><?php p($l->t('Only lock the account if you did not make these changes. Locking does this at once:')); ?></p>
		<ul class="ids-lock__effects">
			<li><?php p($l->t('Every session and app password of the account ends, on every device.')); ?></li>
			<li><?php p($l->t('The account is disabled. Nobody can log in, you neither.')); ?></li>
			<li><?php p($l->t('The administrators are told. Only they can enable the account again.')); ?></li>
		</ul>

		<?php if ($error !== null): ?>
			<p class="ids-page__error" id="ids-lock-error" role="alert"><?php p($error); ?></p>
		<?php endif; ?>

		<form class="ids-page__form" method="post" action="<?php p($_['action'] ?? ''); ?>">
			<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']); ?>">
			<input type="hidden" name="token" value="<?php p($_['token'] ?? ''); ?>">
			<input type="hidden" name="nonce" value="<?php p($_['nonce'] ?? ''); ?>">
			<button class="ids-page__submit ids-lock__danger" type="submit"
				<?php if ($error !== null): ?>aria-describedby="ids-lock-error"<?php endif; ?>>
				<?php p($l->t('Lock the account')); ?>
			</button>
		</form>
		<p class="ids-page__warning"><?php p($l->t('If you made the changes yourself, just close this page. Nothing happens unless you press the button.')); ?></p>
	<?php elseif ($mode === 'locked'): ?>
		<div class="ids-page__icon ids-page__icon--done" aria-hidden="true"></div>
		<h2 class="ids-page__title"><?php p($l->t('The account is locked')); ?></h2>
		<p class="ids-page__notice" role="status"><?php p(($_['disabled'] ?? true) ? $l->t('Every session and app password ended, and the account is disabled. The administrators were told.') : $l->t('Every session and app password ended. The administrators were told and check the account.')); ?></p>
		<p class="ids-page__lead"><?php p($l->t('Contact your administrators to get back in. They check the email address of the account with you, enable it again and help you secure it.')); ?></p>
		<p class="ids-page__hint"><?php p($l->t('Change the password of your email account too, if someone may have had access to it.')); ?></p>
	<?php elseif ($mode === 'used'): ?>
		<div class="ids-page__icon ids-page__icon--done" aria-hidden="true"></div>
		<h2 class="ids-page__title"><?php p($l->t('This link was used already')); ?></h2>
		<p class="ids-page__lead"><?php p($l->t('The account was locked with it, and the administrators were told. Contact them to get back in.')); ?></p>
	<?php elseif ($mode === 'expired'): ?>
		<div class="ids-page__icon ids-page__icon--blocked" aria-hidden="true"></div>
		<h2 class="ids-page__title"><?php p($l->t('This link has expired')); ?></h2>
		<p class="ids-page__lead"><?php p($l->t('Lock links work for 7 days. If someone else may still be using the account, contact your administrators.')); ?></p>
	<?php else: ?>
		<div class="ids-page__icon ids-page__icon--blocked" aria-hidden="true"></div>
		<h2 class="ids-page__title"><?php p($l->t('This link does not work')); ?></h2>
		<p class="ids-page__lead"><?php p($l->t('Check that you opened the whole link from the email. If someone else may be using the account, contact your administrators.')); ?></p>
	<?php endif; ?>

	<div class="ids-page__actions">
		<a href="<?php p($_['login_url']); ?>"><?php p($l->t('Go to the login page')); ?></a>
	</div>
</div>
