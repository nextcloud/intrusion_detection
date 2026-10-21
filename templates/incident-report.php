<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * The printable incident report: a complete, self-contained page that loads
 * nothing. Every value comes from ReportRenderer::view() as plain text and
 * is escaped here with p().
 *
 * @var array<string, mixed> $_
 */
?>
<!DOCTYPE html>
<html lang="<?php p($_['language']); ?>">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?php p($_['title']); ?></title>
<style>
:root {
	--text: #1f2328;
	--muted: #5b636e;
	--border: #d5d9de;
	--surface: #f6f7f9;
	--background: #ffffff;
	--accent: #00679e;
	--low: #5b636e;
	--medium: #0b6bb5;
	--high: #a15c00;
	--critical: #c11a1a;
	color-scheme: light;
}
@media screen and (prefers-color-scheme: dark) {
	:root {
		--text: #e6e8eb;
		--muted: #a2aab3;
		--border: #3a4049;
		--surface: #20242a;
		--background: #16191d;
		--accent: #6cb8ec;
		--low: #a2aab3;
		--medium: #78b7f0;
		--high: #f0b35c;
		--critical: #ff8080;
		color-scheme: dark;
	}
}
* { box-sizing: border-box; }
html { background: var(--background); }
body {
	margin: 0 auto;
	max-width: 880px;
	padding: 40px 24px 64px;
	color: var(--text);
	background: var(--background);
	font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
	overflow-wrap: anywhere;
}
h1, h2, h3, h4 { line-height: 1.25; margin: 0; }
h1 { font-size: 28px; margin-block: 4px 16px; }
h2 { font-size: 19px; margin-block: 0 12px; }
h3 { font-size: 14px; margin-block: 0 6px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
h4 { font-size: 16px; }
p { margin: 0 0 6px; }
ul { margin: 0; padding-inline-start: 20px; }
li { margin-block: 2px; }
.eyebrow { color: var(--accent); font-weight: 600; font-size: 13px; letter-spacing: .04em; text-transform: uppercase; }
.meta { display: grid; grid-template-columns: max-content 1fr; gap: 4px 16px; margin: 0; color: var(--muted); }
.meta dt { font-weight: 600; }
.meta dd { margin: 0; }
section { margin-block-start: 36px; }
.summary { padding: 24px; border: 1px solid var(--border); border-radius: 12px; background: var(--surface); }
.headline { font-size: 17px; font-weight: 600; margin-block-end: 16px; }
.facts { display: flex; flex-wrap: wrap; gap: 12px 32px; margin: 0 0 20px; }
.facts div { min-width: 160px; }
.facts dt { color: var(--muted); font-size: 13px; }
.facts dd { margin: 0; font-weight: 600; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 20px 32px; }
.empty { color: var(--muted); margin: 0; }
.truncated { padding: 10px 14px; border-inline-start: 4px solid var(--high); background: var(--surface); }
.day { margin-block: 28px 10px; padding-block-end: 6px; border-block-end: 1px solid var(--border); text-transform: none; letter-spacing: 0; font-size: 15px; color: var(--text); }
ol.entries { list-style: none; margin: 0; padding: 0; }
.entry { display: grid; grid-template-columns: 64px 1fr; gap: 16px; padding-block: 12px; border-block-end: 1px solid var(--border); break-inside: avoid; page-break-inside: avoid; }
.entry:last-child { border-block-end: none; }
.time { font-variant-numeric: tabular-nums; color: var(--muted); font-weight: 600; padding-block-start: 1px; }
.body { padding-inline-start: 14px; border-inline-start: 3px solid var(--border); }
.sev-low .body { border-inline-start-color: var(--low); }
.sev-medium .body { border-inline-start-color: var(--medium); }
.sev-high .body { border-inline-start-color: var(--high); }
.sev-critical .body { border-inline-start-color: var(--critical); }
.labels { color: var(--muted); font-size: 13px; font-weight: 600; margin-block-end: 2px; }
.sub { margin-block: 8px 2px; font-size: 13px; font-weight: 600; color: var(--muted); }
.note { margin-block-start: 6px; font-style: italic; color: var(--muted); }
.refs { margin-block-start: 8px; font-size: 13px; color: var(--muted); }
.refs span + span::before { content: " · "; }
a { color: var(--accent); }
footer { margin-block-start: 48px; padding-block-start: 12px; border-block-start: 1px solid var(--border); color: var(--muted); font-size: 13px; }
@media (max-width: 560px) {
	body { padding: 24px 16px 48px; }
	.entry { grid-template-columns: 1fr; gap: 4px; }
	.meta { grid-template-columns: 1fr; }
}
@media print {
	@page { margin: 18mm 16mm; }
	:root { --background: #ffffff; --surface: #ffffff; }
	body { max-width: none; padding: 0; font-size: 11pt; }
	.summary { border-color: #999; }
	section { break-before: auto; }
	h2, h3, .day { break-after: avoid; page-break-after: avoid; }
	a[href]::after { content: " (" attr(href) ")"; font-size: 9pt; color: var(--muted); }
}
</style>
</head>
<body>
<header>
	<p class="eyebrow"><?php p($_['eyebrow']); ?></p>
	<h1><?php p($_['subject']); ?></h1>
	<dl class="meta">
		<?php foreach ($_['meta'] as [$label, $value]): ?>
			<dt><?php p($label); ?></dt>
			<dd><?php p($value); ?></dd>
		<?php endforeach; ?>
	</dl>
</header>

<section class="summary" aria-labelledby="summary-heading">
	<h2 id="summary-heading"><?php p($_['summaryHeading']); ?></h2>
	<p class="headline"><?php p($_['headline']); ?></p>
	<dl class="facts">
		<?php foreach ($_['keyFacts'] as [$label, $value]): ?>
			<div>
				<dt><?php p($label); ?></dt>
				<dd><?php p($value); ?></dd>
			</div>
		<?php endforeach; ?>
	</dl>
	<div class="grid">
		<?php foreach ($_['sections'] as $section): ?>
			<div>
				<h3><?php p($section['heading']); ?></h3>
				<?php if ($section['items'] === []): ?>
					<p class="empty"><?php p($section['empty']); ?></p>
				<?php else: ?>
					<ul>
						<?php foreach ($section['items'] as $item): ?>
							<li><?php p($item); ?></li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</div>
		<?php endforeach; ?>
	</div>
</section>

<section aria-labelledby="timeline-heading">
	<h2 id="timeline-heading"><?php p($_['timelineHeading']); ?></h2>
	<?php if ($_['truncated'] !== null): ?>
		<p class="truncated"><?php p($_['truncated']); ?></p>
	<?php endif; ?>
	<?php if ($_['days'] === []): ?>
		<p class="empty"><?php p($_['emptyTimeline']); ?></p>
	<?php endif; ?>
	<?php foreach ($_['days'] as $day): ?>
		<h3 class="day"><?php p($day['label']); ?></h3>
		<ol class="entries">
			<?php foreach ($day['entries'] as $entry): ?>
				<li class="entry sev-<?php p($entry['severity']); ?>">
					<div class="time"><?php p($entry['time']); ?></div>
					<div class="body">
						<p class="labels"><?php p($entry['labels']); ?></p>
						<h4><?php p($entry['title']); ?></h4>
						<?php foreach ($entry['details'] as $sentence): ?>
							<p><?php p($sentence); ?></p>
						<?php endforeach; ?>
						<?php if ($entry['done'] !== []): ?>
							<p class="sub"><?php p($entry['doneHeading']); ?></p>
							<ul>
								<?php foreach ($entry['done'] as $sentence): ?>
									<li><?php p($sentence); ?></li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
						<?php if ($entry['note'] !== null): ?>
							<p class="note"><?php p($entry['note']); ?></p>
						<?php endif; ?>
						<?php if ($entry['meta'] !== []): ?>
							<p class="refs">
								<?php foreach ($entry['meta'] as $item): ?><span><?php p($item); ?></span><?php endforeach; ?>
							</p>
						<?php endif; ?>
					</div>
				</li>
			<?php endforeach; ?>
		</ol>
	<?php endforeach; ?>
</section>

<?php if ($_['notes'] !== []): ?>
	<section aria-labelledby="notes-heading">
		<h2 id="notes-heading"><?php p($_['notesHeading']); ?></h2>
		<ul>
			<?php foreach ($_['notes'] as $note): ?>
				<li>
					<?php p($note['text']); ?>
					<?php if ($note['url'] !== null): ?>
						<a href="<?php p($note['url']); ?>" rel="noreferrer noopener"><?php p($note['linkLabel']); ?></a>
					<?php endif; ?>
				</li>
			<?php endforeach; ?>
		</ul>
	</section>
<?php endif; ?>

<footer>
	<p><?php p($_['footer']); ?></p>
</footer>
</body>
</html>
