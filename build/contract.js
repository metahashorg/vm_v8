Map.prototype.toArray = function() {
    let ar = [];
    this.forEach((x, s) => {
	ar.push([s, x])
    })
    return ar;
};

Object.prototype.toArray = function() {

    if (Array.isArray(this)) {
	return this;
    } else {
	let ar = [];
	for (let i in this) {
	    ar.push([i, this[i]])
	}
	return ar;
    }

};

const dumpClass = obj => {

    let json = {
	items: []
    };

    for (let i in obj) {
	if (obj.hasOwnProperty(i)) {
	    let key = i,
		value = obj[i],
		type = value instanceof Map ? 'Map' : typeof(value);

	    json.items.push({
		key: i,
		type: type,
		value: (value instanceof Map || type == 'object') ? value.toArray() : value
	    })
	}

    }

    return JSON.stringify(json);

};

const makeClass = spec => {
    let parsedSpec = JSON.parse(spec),
	obj = {};

    if (parsedSpec && parsedSpec.items && Array.isArray(parsedSpec.items)) {
	let items = parsedSpec.items;
	for (let i in items) {
	    if (items.hasOwnProperty(i)) {
		let item = items[i];
		if (item.type === 'Map') {
		    obj[item.key] = new Map;
		    for (let v in item.value) {
			if (item.value.hasOwnProperty(v)) {
			    obj[item.key].set(item.value[v][0], item.value[v][1])
			}
		    }
		} else if (obj.type === 'object') {
		    obj[item.key] = {};
		    for (let v in item.value) {
			if (item.value.hasOwnProperty(v)) {
			    obj[item.key][item.value[v][0]] = [item.value[v][1]];
			}
		    }

		} else {
		    obj[item.key] = item.value;
		}
	    }
	}
    }

    return obj;
};










class Contract {

    constructor() {
	this.ammount = 0;    
	this.data = new Map;
    }
  
    add() {
	this.ammount ++;
    }
  
    addPaymentInfo(key, value) {    
	let val = this.data.get(key);
	let curValue = value;
	if(val !== undefined && typeof val === 'number') {
	    value += val;
	}
	this.data.set(key, value);
	this.ammount = this.ammount + curValue;
    }
}


