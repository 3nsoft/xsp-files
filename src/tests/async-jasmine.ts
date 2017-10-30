/* Copyright(c) 2016 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

export function itAsync(expectation: string,
		assertion?: () => Promise<void>, timeout?: number): void {
	if (assertion) {
		it(expectation, done => {
			assertion().then(
				() => done(),
				err => done.fail(err));
		}, timeout);
	} else {
		it(expectation);
	}
}

export function xitAsync(expectation: string,
		assertion?: () => Promise<void>, timeout?: number): void {
	if (assertion) {
		xit(expectation, done => {
			assertion().then(
				() => done(),
				err => done.fail(err));
		}, timeout);
	} else {
		xit(expectation);
	}
}

export function fitAsync(expectation: string,
		assertion?: () => Promise<void>, timeout?: number): void {
	if (assertion) {
		fit(expectation, done => {
			assertion().then(
				() => done(),
				err => done.fail(err));
		}, timeout);
	} else {
		fit(expectation);
	}
}

export function beforeAllAsync(action: () => Promise<void>, timeout?: number) {
	beforeAll(done => {
		action().then(
			() => done(),
			err => done.fail(err));
	}, timeout);
}

export function afterAllAsync(action: () => Promise<void>, timeout?: number) {
	afterAll(done => {
		action().then(
			() => done(),
			err => done.fail(err));
	}, timeout);
}

export function beforeEachAsync(action: () => Promise<void>, timeout?: number) {
	beforeEach(done => {
		action().then(
			() => done(),
			err => done.fail(err));
	}, timeout);
}

export function afterEachAsync(action: () => Promise<void>, timeout?: number) {
	afterEach(done => {
		action().then(
			() => done(),
			err => done.fail(err));
	}, timeout);
}

Object.freeze(exports);