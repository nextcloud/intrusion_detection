# SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# make build appstore: build the frontend, then pack the app store tarball
# build/artifacts/intrusion_detection.tar.gz. The release workflow builds
# and signs it itself and only calls `make appstore`.

app_name := intrusion_detection
build_dir := build/artifacts

# Everything the app needs at runtime. Sources, tests, dev tools and
# configs stay out of the package.
runtime_files := appinfo composer css img js l10n lib templates LICENSE LICENSES

.PHONY: build appstore clean

build:
	npm ci
	npm run build

appstore: clean
	@test -f js/settings-admin.mjs || { echo "The frontend is not built: run make build first." >&2; exit 1; }
	mkdir -p $(build_dir)/$(app_name)
	rsync -a --exclude=".*" --exclude="/composer/composer.json" --exclude="/composer/composer.lock" \
		$$(ls -d $(runtime_files) 2>/dev/null) $(build_dir)/$(app_name)/
	tar -czf $(build_dir)/$(app_name).tar.gz -C $(build_dir) $(app_name)

clean:
	rm -rf build
