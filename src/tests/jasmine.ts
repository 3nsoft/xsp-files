/* Copyright(c) 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

// NOTE: due to bad definition file, typescript below is not very type-strict.

let jas = new (require('jasmine'))();

jas.loadConfig({
	spec_dir: 'dist/tests',
	spec_files: [
		'segments/**/*.js',
		'crypt-utils/**/*.js'
	]
});

jas.configureDefaultReporter({
	showColors: true
})

jas.execute();
