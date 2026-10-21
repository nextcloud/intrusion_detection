<!--
  - SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
  - SPDX-License-Identifier: AGPL-3.0-or-later
-->

<script setup lang="ts">
import type { SecureAccount, SecureAccountStepId } from '../secureAccountTypes.ts'

import {
	mdiCheck,
	mdiDeleteOutline,
	mdiDevices,
	mdiEmailOutline,
	mdiHistory,
	mdiKeyOutline,
	mdiOpenInNew,
	mdiShareVariantOutline,
	mdiShieldAccountOutline,
	mdiShieldCheckOutline,
	mdiTwoFactorAuthentication,
} from '@mdi/js'
import { n, t } from '@nextcloud/l10n'
import { computed, onMounted, ref } from 'vue'
import NcAppContent from '@nextcloud/vue/components/NcAppContent'
import NcButton from '@nextcloud/vue/components/NcButton'
import NcContent from '@nextcloud/vue/components/NcContent'
import NcDialog from '@nextcloud/vue/components/NcDialog'
import NcEmptyContent from '@nextcloud/vue/components/NcEmptyContent'
import NcIconSvgWrapper from '@nextcloud/vue/components/NcIconSvgWrapper'
import NcLoadingIcon from '@nextcloud/vue/components/NcLoadingIcon'
import NcNoteCard from '@nextcloud/vue/components/NcNoteCard'
import NcPasswordField from '@nextcloud/vue/components/NcPasswordField'
import NcProgressBar from '@nextcloud/vue/components/NcProgressBar'
import SkeletonBlock from '../components/common/SkeletonBlock.vue'
import TimeStamp from '../components/common/TimeStamp.vue'
import StepCard from '../components/secure/StepCard.vue'
import { useAnnouncer } from '../composables/useAnnouncer.ts'
import { errorMessage, isCancelled } from '../services/api.ts'
import { logger } from '../services/logger.ts'
import {
	changePassword,
	completeStep,
	deleteShare,
	dismissSecureAccount,
	fetchSecureAccount,
	revokeSession,
	startSecureAccount,
} from '../services/secureAccount.ts'
import { APP_ID } from '../utils/format.ts'

const data = ref<SecureAccount | null>(null)
const loadError = ref<string | null>(null)
const busy = ref<string | null>(null)
const stepError = ref<{ step: string, message: string } | null>(null)
const confirmDismiss = ref(false)
const oldPassword = ref('')
const newPassword = ref('')
const { message: announcement, announce } = useAnnouncer()

const progress = computed(() => data.value?.progress ?? null)
const finished = computed(() => progress.value !== null && !progress.value.active && progress.value.closedBy === 'done')
const percent = computed(() => progress.value && progress.value.total > 0 ? Math.round(progress.value.done / progress.value.total * 100) : 0)

const lead = computed(() => {
	switch (progress.value?.reason) {
		case 'reenabled':
			return t(APP_ID, 'Your administrator enabled your account again after it was locked. Go through these steps to make sure nobody else can get in.')
		case 'denied':
			return t(APP_ID, 'You said that something on your account was not you. Nextcloud already ended the sessions involved. Go through these steps to make sure nobody else can get in.')
		case 'detection':
			return t(APP_ID, 'Nextcloud noticed signs that someone else may have had your password. Go through these steps to make sure nobody else can get in.')
		default:
			return t(APP_ID, 'Go through these steps to make sure nobody else can get into your account.')
	}
})

const STEP_TEXTS: Record<SecureAccountStepId, { heading: () => string, icon: string }> = {
	password: { heading: () => t(APP_ID, 'Change your password'), icon: mdiKeyOutline },
	sessions: { heading: () => t(APP_ID, 'Check your devices and sessions'), icon: mdiDevices },
	two_factor: { heading: () => t(APP_ID, 'Turn on two-factor authentication'), icon: mdiTwoFactorAuthentication },
	email: { heading: () => t(APP_ID, 'Check your email address and profile'), icon: mdiEmailOutline },
	shares: { heading: () => t(APP_ID, 'Check what you shared recently'), icon: mdiShareVariantOutline },
	files: { heading: () => t(APP_ID, 'Check recent file changes'), icon: mdiHistory },
}

/**
 * Load the checklist (again).
 */
async function load() {
	loadError.value = null
	try {
		data.value = await fetchSecureAccount()
	} catch (e) {
		logger.error('Could not load the checklist', { error: e })
		loadError.value = errorMessage(e, t(APP_ID, 'The checklist could not be loaded. Please reload the page.'))
	}
}

/**
 * Run a change and show the checklist as it is afterwards.
 *
 * @param key - What is busy, for the loading state of its button
 * @param action - The change
 * @param fallback - What to say when it fails
 * @param done - What to announce when it worked
 */
async function run(key: string, action: () => Promise<SecureAccount | void>, fallback: string, done?: string) {
	busy.value = key
	stepError.value = null
	try {
		const result = await action()
		data.value = result ?? await fetchSecureAccount()
		if (done) {
			announce(done)
		}
	} catch (e) {
		if (!isCancelled(e)) {
			logger.error('Could not update the checklist', { error: e })
			stepError.value = { step: key, message: errorMessage(e, fallback) }
		}
	} finally {
		busy.value = null
	}
}

/**
 * @param step - The step the user checked
 */
function confirmStep(step: SecureAccountStepId) {
	run('step:' + step, () => completeStep(step), t(APP_ID, 'The step could not be saved. Please try again.'), t(APP_ID, 'Step done.'))
}

/**
 * Change the password with the inline form.
 */
function submitPassword() {
	run('step:password', async () => {
		await changePassword(oldPassword.value, newPassword.value)
		oldPassword.value = ''
		newPassword.value = ''
	}, t(APP_ID, 'Your password could not be changed. Check your current password and try again.'), t(APP_ID, 'Your password was changed.'))
}

/**
 * @param id - The session or app password
 * @param name - Its name, for the announcement
 */
function revoke(id: number, name: string) {
	run('session:' + id, () => revokeSession(id), t(APP_ID, 'It could not be revoked. Please try again.'), t(APP_ID, '"{name}" was revoked.', { name }))
}

/**
 * @param id - The full share id
 * @param name - The shared item, for the announcement
 */
function removeShare(id: string, name: string) {
	run('share:' + id, () => deleteShare(id), t(APP_ID, 'The share could not be deleted. Please try again.'), t(APP_ID, 'The share of "{name}" was deleted.', { name }))
}

/**
 * The error of the last change made within a step, if any.
 *
 * @param id - The step
 */
function errorFor(id: SecureAccountStepId): string | null {
	const key = stepError.value?.step ?? ''
	const mine = key === 'step:' + id
		|| (id === 'sessions' && key.startsWith('session:'))
		|| (id === 'shares' && key.startsWith('share:'))
	return mine ? stepError.value!.message : null
}

/**
 * @param via - Who made a change
 * @param actor - The administrator, if one did
 */
function viaText(via: string, actor: string | null): string {
	switch (via) {
		case 'self':
			return t(APP_ID, 'from your account')
		case 'admin':
			return t(APP_ID, 'by the administrator {admin}', { admin: actor ?? '' })
		case 'reset':
			return t(APP_ID, 'with a password reset by email')
		default:
			return t(APP_ID, 'by your administrators or Nextcloud')
	}
}

const dismissButtons = computed(() => [
	{ label: t(APP_ID, 'Keep the checklist'), callback: () => undefined },
	{
		label: t(APP_ID, 'Close the checklist'),
		variant: 'primary' as const,
		callback: () => {
			run('dismiss', dismissSecureAccount, t(APP_ID, 'The checklist could not be closed. Please try again.'), t(APP_ID, 'The checklist was closed.'))
		},
	},
])

onMounted(load)
</script>

<template>
	<NcContent appName="intrusion_detection">
		<NcAppContent :pageHeading="t(APP_ID, 'Secure my account')">
			<main :class="$style.page">
				<p class="hidden-visually" aria-live="polite">
					{{ announcement }}
				</p>

				<div v-if="data === null && loadError === null" :class="$style.page__skeleton" aria-busy="true">
					<SkeletonBlock height="140px" />
					<SkeletonBlock height="64px" />
					<SkeletonBlock height="64px" />
					<SkeletonBlock height="64px" />
				</div>
				<NcNoteCard v-else-if="loadError" type="error" :text="loadError" />

				<template v-else-if="data && progress">
					<header :class="[$style.hero, finished ? $style.hero_done : null]">
						<span :class="$style.hero__icon" aria-hidden="true">
							<NcIconSvgWrapper :path="finished ? mdiShieldCheckOutline : mdiShieldAccountOutline" :size="32" />
						</span>
						<div :class="$style.hero__text">
							<h2 :class="$style.hero__title">
								{{ t(APP_ID, 'Secure my account') }}
							</h2>
							<p v-if="progress.active" :class="$style.hero__lead">
								{{ lead }}
							</p>
							<p v-else-if="finished" :class="$style.hero__lead">
								{{ t(APP_ID, 'All done. Your account is as safe as you can make it. Thank you for checking.') }}
							</p>
							<p v-else :class="$style.hero__lead">
								{{ t(APP_ID, 'If you think someone else got into your account, this checklist guides you through securing it: a new password, your devices, two-factor authentication, your email address and what you shared.') }}
							</p>
							<div v-if="progress.active || finished" :class="$style.hero__progress">
								<span :class="$style.hero__count">
									{{ n(APP_ID, '{done} of %n step done', '{done} of %n steps done', progress.total, { done: progress.done }) }}
								</span>
								<NcProgressBar
									:value="percent"
									size="medium"
									:aria-label="t(APP_ID, 'Progress of the checklist')" />
							</div>
						</div>
						<div v-if="!progress.active" :class="$style.hero__actions">
							<NcButton variant="primary" :disabled="busy !== null" @click="run('start', startSecureAccount, t(APP_ID, 'The checklist could not be started. Please try again.'))">
								<template #icon>
									<NcLoadingIcon v-if="busy === 'start'" :size="20" />
									<NcIconSvgWrapper v-else :path="mdiShieldAccountOutline" />
								</template>
								{{ finished ? t(APP_ID, 'Go through it again') : t(APP_ID, 'Start the checklist') }}
							</NcButton>
						</div>
					</header>

					<NcEmptyContent
						v-if="!progress.active && !finished"
						:name="t(APP_ID, 'Nothing to do right now')"
						:description="t(APP_ID, 'Nextcloud starts this checklist for you when something suspicious happened to your account.')">
						<template #icon>
							<NcIconSvgWrapper :path="mdiShieldCheckOutline" />
						</template>
					</NcEmptyContent>

					<ol v-if="progress.active" :class="$style.steps">
						<StepCard
							v-for="(item, index) in progress.steps"
							:key="item.id"
							:number="index + 1"
							:heading="STEP_TEXTS[item.id].heading()"
							:icon="STEP_TEXTS[item.id].icon"
							:done="item.done"
							:skipped="item.skipped">
							<template v-if="item.id === 'password'">
								<p v-if="item.done" :class="$style.text">
									{{ t(APP_ID, 'You chose a new password.') }}
									<TimeStamp v-if="item.doneAt" :timestamp="item.doneAt" />
								</p>
								<NcNoteCard v-else-if="item.managed" type="info" :text="t(APP_ID, 'Your password is managed by your organisation. Ask your administrator to reset it. This step is marked done when they have.')" />
								<form v-else :class="$style.form" @submit.prevent="submitPassword">
									<p :class="$style.text">
										{{ t(APP_ID, 'Someone else may know your current password. Choose a new one that you do not use anywhere else. Apps connected with an app password keep working.') }}
									</p>
									<NcPasswordField
										v-model="oldPassword"
										:label="t(APP_ID, 'Current password')"
										autocomplete="current-password"
										required />
									<NcPasswordField
										v-model="newPassword"
										:label="t(APP_ID, 'New password')"
										autocomplete="new-password"
										checkPasswordStrength
										required />
									<div>
										<NcButton type="submit" variant="primary" :disabled="busy !== null || oldPassword === '' || newPassword === ''">
											<template #icon>
												<NcLoadingIcon v-if="busy === 'step:password'" :size="20" />
												<NcIconSvgWrapper v-else :path="mdiKeyOutline" />
											</template>
											{{ t(APP_ID, 'Change password') }}
										</NcButton>
									</div>
								</form>
							</template>

							<template v-else-if="item.id === 'sessions'">
								<p :class="$style.text">
									{{ t(APP_ID, 'These browsers and apps can open your account. Revoke everything you do not recognise. Entries created after the suspicious event are marked.') }}
								</p>
								<ul :class="$style.list">
									<li v-for="session in data.sessions" :key="session.id" :class="[$style.row, session.afterEvent ? $style.row_new : null]">
										<div :class="$style.row__main">
											<span :class="$style.row__title">{{ session.name || t(APP_ID, 'Unnamed') }}</span>
											<span :class="$style.row__meta">
												<span>{{ session.kind === 'app_password' ? t(APP_ID, 'App password') : t(APP_ID, 'Browser session') }}</span>
												<span v-if="session.address">{{ t(APP_ID, 'created from {address}', { address: session.address }) }}</span>
												<span v-if="session.lastActivity">
													{{ t(APP_ID, 'last used') }} <TimeStamp :timestamp="session.lastActivity" />
												</span>
											</span>
										</div>
										<span v-if="session.current" :class="[$style.badge, $style.badge_neutral]">{{ t(APP_ID, 'This device') }}</span>
										<span v-else-if="session.afterEvent" :class="[$style.badge, $style.badge_warning]">{{ t(APP_ID, 'New since the event') }}</span>
										<NcButton
											v-if="!session.current"
											variant="tertiary"
											:aria-label="t(APP_ID, 'Revoke {name}', { name: session.name })"
											:disabled="busy !== null"
											@click="revoke(session.id, session.name)">
											<template #icon>
												<NcLoadingIcon v-if="busy === 'session:' + session.id" :size="20" />
												<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
											</template>
											{{ t(APP_ID, 'Revoke') }}
										</NcButton>
									</li>
								</ul>
							</template>

							<template v-else-if="item.id === 'two_factor'">
								<p v-if="item.skipped" :class="$style.text">
									{{ t(APP_ID, 'No second factor is available on this server, so this step is left out.') }}
								</p>
								<p v-else-if="item.done" :class="$style.text">
									{{ t(APP_ID, 'Two-factor authentication is on: a stolen password alone is not enough to get in.') }}
								</p>
								<template v-else>
									<p :class="$style.text">
										{{ t(APP_ID, 'With a second factor, such as an app on your phone or a security key, a stolen password alone is not enough to get in. This step is done as soon as you have set one up.') }}
									</p>
									<div>
										<NcButton :href="data.links.security" variant="secondary">
											<template #icon>
												<NcIconSvgWrapper :path="mdiOpenInNew" />
											</template>
											{{ t(APP_ID, 'Set up two-factor authentication') }}
										</NcButton>
									</div>
								</template>
							</template>

							<template v-else-if="item.id === 'email'">
								<p v-if="data.email" :class="$style.text">
									{{ t(APP_ID, 'Nextcloud reaches you at {email}. If this is not your address, correct it now: someone may have changed it.', { email: data.email }) }}
								</p>
								<NcNoteCard v-else type="warning" :text="t(APP_ID, 'Add an email address so Nextcloud can reach you if this happens again.')" />
								<h4 :class="$style.subheading">
									{{ t(APP_ID, 'Security changes since a week before the event') }}
								</h4>
								<p v-if="data.changes.length === 0" :class="$style.text">
									{{ t(APP_ID, 'None.') }}
								</p>
								<ul v-else :class="$style.list">
									<li v-for="change in data.changes" :key="change.id" :class="$style.row">
										<div :class="$style.row__main">
											<span :class="$style.row__title">
												{{ change.label }}
												<template v-if="change.type === 'email_changed'">
													({{ t(APP_ID, '{previous} to {new}', { previous: change.previous ?? t(APP_ID, 'none'), new: change.new ?? t(APP_ID, 'none') }) }})
												</template>
											</span>
											<span :class="$style.row__meta">
												<TimeStamp :timestamp="change.createdAt" />
												<span>{{ viaText(change.via, change.actor) }}</span>
												<span v-if="change.address">{{ t(APP_ID, 'from {address}', { address: change.address }) }}</span>
											</span>
										</div>
									</li>
								</ul>
							</template>

							<template v-else-if="item.id === 'shares'">
								<p :class="$style.text">
									{{ t(APP_ID, 'Public links, email shares and shares with other servers you created since a week before the event. Delete the ones you did not make.') }}
								</p>
								<p v-if="data.shares.length === 0" :class="$style.text">
									{{ t(APP_ID, 'You created none in this time.') }}
								</p>
								<ul v-else :class="$style.list">
									<li v-for="share in data.shares" :key="share.id" :class="$style.row">
										<div :class="$style.row__main">
											<span :class="$style.row__title">{{ share.name }}</span>
											<span :class="$style.row__meta">
												<span>{{ share.type === 'link' ? t(APP_ID, 'Public link') : (share.type === 'email' ? t(APP_ID, 'Shared by email with {recipient}', { recipient: share.recipient ?? '' }) : t(APP_ID, 'Shared with {recipient}', { recipient: share.recipient ?? '' })) }}</span>
												<TimeStamp :timestamp="share.createdAt" />
												<span v-if="share.type !== 'federated'">{{ share.hasPassword ? t(APP_ID, 'with a password') : t(APP_ID, 'no password') }}</span>
											</span>
										</div>
										<NcButton
											variant="tertiary"
											:aria-label="t(APP_ID, 'Delete the share of {name}', { name: share.name })"
											:disabled="busy !== null"
											@click="removeShare(share.id, share.name)">
											<template #icon>
												<NcLoadingIcon v-if="busy === 'share:' + share.id" :size="20" />
												<NcIconSvgWrapper v-else :path="mdiDeleteOutline" />
											</template>
											{{ t(APP_ID, 'Delete') }}
										</NcButton>
									</li>
								</ul>
							</template>

							<template v-else-if="item.id === 'files'">
								<p :class="$style.text">
									{{ t(APP_ID, 'Look for files that were changed, moved or deleted without you. Deleted files stay in the trash bin for a while, and earlier versions of a file can be restored from its details in Files.') }}
								</p>
								<div :class="$style.links">
									<NcButton v-if="data.links.activity" :href="data.links.activity" variant="secondary">
										<template #icon>
											<NcIconSvgWrapper :path="mdiOpenInNew" />
										</template>
										{{ t(APP_ID, 'Open your activity') }}
									</NcButton>
									<NcButton v-if="data.links.trash" :href="data.links.trash" variant="secondary">
										<template #icon>
											<NcIconSvgWrapper :path="mdiOpenInNew" />
										</template>
										{{ t(APP_ID, 'Open the trash bin') }}
									</NcButton>
								</div>
							</template>

							<NcNoteCard v-if="errorFor(item.id)" type="error" :text="errorFor(item.id)!" />

							<div v-if="item.userConfirms && !item.done" :class="$style.confirm">
								<NcButton variant="primary" :disabled="busy !== null" @click="confirmStep(item.id)">
									<template #icon>
										<NcLoadingIcon v-if="busy === 'step:' + item.id" :size="20" />
										<NcIconSvgWrapper v-else :path="mdiCheck" />
									</template>
									{{ item.id === 'email' ? t(APP_ID, 'My email address and profile are correct') : t(APP_ID, 'I have checked this') }}
								</NcButton>
							</div>
						</StepCard>
					</ol>

					<footer v-if="progress.active" :class="$style.footer">
						<p :class="$style.text">
							{{ t(APP_ID, 'Something does not look right? Contact your administrator: they can see what happened to your account.') }}
						</p>
						<NcButton variant="tertiary" @click="confirmDismiss = true">
							{{ t(APP_ID, 'Close the checklist') }}
						</NcButton>
					</footer>
					<NcNoteCard v-if="stepError && stepError.step === 'dismiss'" type="error" :text="stepError.message" />
				</template>

				<NcDialog
					v-model:open="confirmDismiss"
					:name="t(APP_ID, 'Close the checklist?')"
					:message="t(APP_ID, 'The steps you have not done yet stay undone. You can start the checklist again at any time.')"
					:buttons="dismissButtons" />
			</main>
		</NcAppContent>
	</NcContent>
</template>

<style module>
.page {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 4);
	box-sizing: border-box;
	width: 100%;
	max-width: 880px;
	margin: 0 auto;
	padding: calc(var(--default-grid-baseline) * 8) calc(var(--default-grid-baseline) * 4);
}

.page__skeleton {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
}

.hero {
	display: flex;
	flex-wrap: wrap;
	align-items: flex-start;
	gap: calc(var(--default-grid-baseline) * 5);
	padding: calc(var(--default-grid-baseline) * 6);
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-container, var(--border-radius-large));
	background-color: color-mix(in srgb, var(--color-primary-element) 8%, var(--color-main-background));
}

.hero_done {
	background-color: color-mix(in srgb, var(--color-success) 12%, var(--color-main-background));
}

.hero__icon {
	display: inline-flex;
	align-items: center;
	justify-content: center;
	flex: 0 0 auto;
	width: 56px;
	height: 56px;
	border-radius: 50%;
	background-color: var(--color-main-background);
	color: var(--color-primary-element);
}

.hero_done .hero__icon {
	color: var(--color-success-text);
}

.hero__text {
	display: flex;
	flex: 1 1 320px;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 2);
	min-width: 0;
}

.hero__title {
	margin: 0;
	font-size: 1.6em;
	line-height: 1.25;
}

.hero__lead {
	margin: 0;
	max-width: 60ch;
	line-height: 1.5;
}

.hero__progress {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 1.5);
	max-width: 420px;
	margin-block-start: calc(var(--default-grid-baseline) * 2);
}

.hero__count {
	font-weight: 600;
}

.hero__actions {
	display: flex;
	align-items: center;
}

.steps {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	margin: 0;
	padding: 0;
	list-style: none;
}

.text {
	margin: 0;
	line-height: 1.5;
}

.subheading {
	margin: calc(var(--default-grid-baseline) * 2) 0 0;
	font-size: 1em;
	font-weight: 600;
}

.form {
	display: flex;
	flex-direction: column;
	gap: calc(var(--default-grid-baseline) * 3);
	max-width: 420px;
}

.list {
	display: flex;
	flex-direction: column;
	margin: 0;
	padding: 0;
	border: 1px solid var(--color-border);
	border-radius: var(--border-radius-element);
	list-style: none;
}

.row {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	gap: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	padding: calc(var(--default-grid-baseline) * 2) calc(var(--default-grid-baseline) * 3);
	border-bottom: 1px solid var(--color-border);
}

.row:last-child {
	border-bottom: none;
}

.row_new {
	border-inline-start: 3px solid var(--color-warning);
}

.row__main {
	display: flex;
	flex: 1 1 240px;
	flex-direction: column;
	min-width: 0;
}

.row__title {
	overflow-wrap: anywhere;
	font-weight: 600;
}

.row__meta {
	display: flex;
	flex-wrap: wrap;
	gap: 0 calc(var(--default-grid-baseline) * 3);
	color: var(--color-text-maxcontrast);
	font-size: 0.9em;
}

.badge {
	padding-inline: calc(var(--default-grid-baseline) * 2);
	border-radius: var(--border-radius-element);
	font-size: 0.85em;
	font-weight: 600;
	line-height: 24px;
	white-space: nowrap;
}

.badge_neutral {
	background-color: var(--color-background-dark);
	color: var(--color-main-text);
}

.badge_warning {
	background-color: color-mix(in srgb, var(--color-warning) 18%, var(--color-main-background));
	color: var(--color-warning-text);
}

.links,
.confirm {
	display: flex;
	flex-wrap: wrap;
	gap: calc(var(--default-grid-baseline) * 2);
}

.footer {
	display: flex;
	flex-wrap: wrap;
	align-items: center;
	justify-content: space-between;
	gap: calc(var(--default-grid-baseline) * 3);
	padding: 0 calc(var(--default-grid-baseline) * 2);
	color: var(--color-text-maxcontrast);
}

@media (max-width: 600px) {
	.page {
		padding: calc(var(--default-grid-baseline) * 4);
	}

	.hero {
		padding: calc(var(--default-grid-baseline) * 4);
	}
}
</style>
