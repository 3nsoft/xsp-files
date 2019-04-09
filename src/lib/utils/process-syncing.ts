/*
 Copyright (C) 2015, 2017 - 2018 3NSoft Inc.
 
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

/**
 * Standard Promise has no finally() method, when all respected libraries do.
 * Inside of an async function one may use try-finally clause. But, when we
 * work with raw promises, we need a compact finalization routine. And this is
 * it for synchronous completion.
 * @param promise
 * @param fin is a synchronous function that performs necessary
 * finalization/cleanup. Use finalizeAsync, when finalization is asynchronous.
 * @return a finalized promise
 */
export function finalize<T>(promise: Promise<T>, fin: () => void): Promise<T> {
	return promise
	.then((res) => {
		fin();
		return res;
	}, (err) => {
		fin();
		throw err;
	})
}

/**
 * This represents a function that will create a promise, potentially starting
 * some background process, only when it is called. Such wrap of code is needed
 * for scheduling, as very often any start of an action must be postponed till
 * later time. Scheduler needs a not-yet-started activity, as scheduler has
 * control action's start.
 */
export type Action<T> = () => Promise<T>;

/**
 * This is a container of process. It allows to track if a process is already
 * in progress. It also allows to chain process, when needed.
 * 
 * Common use of such class is to reuse getting of some expensive resource, or
 * do ning something as an exclusive process.
 */
export class SingleProc {
	
	private promise: Promise<any>|undefined = undefined;
	
	constructor() {
		Object.seal(this);
	}
	
	private insertPromise<T>(promise: Promise<T>): Promise<T> {
		promise = finalize(promise, () => {
			if (this.promise === promise) {
				this.promise = undefined;
			}
		});
		this.promise = promise;
		return promise;
	}
	
	getP<T>(): Promise<T>|undefined {
		return this.promise;
	}
	
	addStarted<T>(promise: Promise<T>): Promise<T> {
		if (this.promise) { throw new Error('Process is already in progress.'); }
		return this.insertPromise(promise);
	}
	
	start<T>(action: Action<T>): Promise<T> {
		if (this.promise) { throw new Error('Process is already in progress.'); }
		return this.insertPromise(action());
	}
	
	startOrChain<T>(action: Action<T>): Promise<T> {
		if (this.promise) {
			const next = this.promise.then(() => { return action(); });
			return this.insertPromise(next);
		} else {
			return this.insertPromise(action());
		}
	}
	
}
Object.freeze(SingleProc.prototype);
Object.freeze(SingleProc);

export function makeSyncedFunc<T extends Function>(
		syncProc: SingleProc, thisArg: any, func: T): T {
	return ((...args) => syncProc.startOrChain(() => func.apply(thisArg, args))) as any as T;
}

Object.freeze(exports);