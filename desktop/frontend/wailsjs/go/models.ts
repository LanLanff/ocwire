export namespace main {
	
	export class ActivityEntry {
	    t: string;
	    kind: string;
	    peer?: string;
	    clientId?: string;
	    op?: string;
	    detail?: string;
	    ok?: boolean;
	    ms?: number;
	    bytes?: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new ActivityEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.t = source["t"];
	        this.kind = source["kind"];
	        this.peer = source["peer"];
	        this.clientId = source["clientId"];
	        this.op = source["op"];
	        this.detail = source["detail"];
	        this.ok = source["ok"];
	        this.ms = source["ms"];
	        this.bytes = source["bytes"];
	        this.error = source["error"];
	    }
	}
	export class ClientInfo {
	    id: string;
	    label?: string;
	    createdAt?: string;
	    used: boolean;
	    disabled: boolean;
	    online: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ClientInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.label = source["label"];
	        this.createdAt = source["createdAt"];
	        this.used = source["used"];
	        this.disabled = source["disabled"];
	        this.online = source["online"];
	    }
	}
	export class ManagerTarget {
	    name: string;
	    state: string;
	    peer: string;
	    error: string;
	    requests: number;
	
	    static createFrom(source: any = {}) {
	        return new ManagerTarget(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.state = source["state"];
	        this.peer = source["peer"];
	        this.error = source["error"];
	        this.requests = source["requests"];
	    }
	}
	export class ManagerStateView {
	    running: boolean;
	    clientName?: string;
	    targets: ManagerTarget[];
	
	    static createFrom(source: any = {}) {
	        return new ManagerStateView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.clientName = source["clientName"];
	        this.targets = this.convertValues(source["targets"], ManagerTarget);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ProfileInfo {
	    name: string;
	    hub: string;
	    deviceId?: string;
	    token: boolean;
	    canOperate: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProfileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.hub = source["hub"];
	        this.deviceId = source["deviceId"];
	        this.token = source["token"];
	        this.canOperate = source["canOperate"];
	    }
	}
	export class State {
	    activated: boolean;
	    name: string;
	    deviceId?: string;
	    hub?: string;
	    running: boolean;
	    connected: boolean;
	    peerName?: string;
	    autostart: boolean;
	    disabled: boolean;
	    lastError?: string;
	    defaultHub: string;
	    version: string;
	    readonly: boolean;
	
	    static createFrom(source: any = {}) {
	        return new State(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.activated = source["activated"];
	        this.name = source["name"];
	        this.deviceId = source["deviceId"];
	        this.hub = source["hub"];
	        this.running = source["running"];
	        this.connected = source["connected"];
	        this.peerName = source["peerName"];
	        this.autostart = source["autostart"];
	        this.disabled = source["disabled"];
	        this.lastError = source["lastError"];
	        this.defaultHub = source["defaultHub"];
	        this.version = source["version"];
	        this.readonly = source["readonly"];
	    }
	}

}

