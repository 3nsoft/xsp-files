/*
 Copyright(c) 2022 3NSoft Inc.
 
 This program is free software: you can redistribute it and/or modify it under
 the terms of the GNU General Public License as published by the Free Software
 Foundation, either version 3 of the License, or (at your option) any later
 version.
 
 This program is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 See the GNU General Public License for more details.
 
 You should have received a copy of the GNU General Public License along with
 this program. If not, see <http://www.gnu.org/licenses/>.
*/


export abstract class LabeledWorkQueues {

	private readonly workQueues = new Map<number, number>();

	protected addToWorkQueue(workLabel: number): void {
		const inQueue = this.workQueues.get(workLabel);
		this.workQueues.set(workLabel, (inQueue ? inQueue+1 : 1));
	}

	protected removeFromWorkQueue(workLabel: number): void {
		const inQueue = this.workQueues.get(workLabel);
		if (inQueue && (inQueue > 1)) {
			this.workQueues.set(workLabel, inQueue-1);
		} else {
			this.workQueues.delete(workLabel);
		}
	}

	protected abstract idleWorkers(): number;

	canStartUnderWorkLabel(workLabel: number): number {
		const maxIdle = this.idleWorkers() - this.workQueues.size;
		if (maxIdle <= 0) {
			return (this.workQueues.has(workLabel) ? 0 : 1);
		}
		const inQueue = this.workQueues.get(workLabel);
		return (inQueue ? Math.max(0, inQueue) : maxIdle);
	}

	async wrapOpPromise<T>(
		workLabel: number, workOp: Promise<T>
	): Promise<T> {
		this.addToWorkQueue(workLabel);
		try {
			return await workOp;
		} finally {
			this.removeFromWorkQueue(workLabel);
		}
	}

}
Object.freeze(LabeledWorkQueues.prototype);
Object.freeze(LabeledWorkQueues);


export class InProcAsyncExecutor extends LabeledWorkQueues {

	private opsInExec = 0;

	constructor(
		private readonly maxOfRunning = 1
	) {
		super();
		Object.seal(this);
	}

	idleWorkers(): number {
		return Math.max((this.maxOfRunning - this.opsInExec), 0);
	}

	async execOpOnNextTick<T>(workLabel: number, op: () => T): Promise<T> {
		this.opsInExec += 1;
		try {
			return await this.wrapOpPromise(workLabel, onNextTick(op));
		} finally {
			this.opsInExec -= 1;
		}
	}

}
Object.freeze(InProcAsyncExecutor.prototype);
Object.freeze(InProcAsyncExecutor);


async function onNextTick<T>(action: () => T): Promise<T> {
	return new Promise<T>((resolve, reject) => process.nextTick(() => {
		try {
			resolve(action());
		} catch (err) {
			reject(err);
		}
	}));
}


Object.freeze(exports);