/*
 Copyright (C) 2016 3NSoft Inc.
 
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 See the GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along with
 this program. If not, see <http://www.gnu.org/licenses/>. */

// NOTE: due to bad definition file, typescript below is not very type-strict.

let jas = new (require('jasmine'))();

jas.loadConfig({
	spec_dir: 'dist/tests',
	spec_files: [
		'file/**/*.js'
	]
});

jas.configureDefaultReporter({
	showColors: true
})

jas.execute();
