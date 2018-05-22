var contExp = new Contract();
let strDump = '{"items":[{"key":"ammount","type":"number","value":220},{"key":"data","type":"Map","value":[["Jane",100],["Bob",120]]}]}';
contExp = Object.assign(contExp, makeClass(strDump));