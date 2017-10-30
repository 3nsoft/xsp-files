/* Copyright(c) 2015 3NSoft Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/. */

export function bind<T extends Function>(thisArg: any, func: T): T {
	return func.bind(thisArg);
}

Object.freeze(exports);