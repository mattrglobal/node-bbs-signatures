import { generateTestVector } from "./helper";

//console.log(JSON.stringify(generateTestVector("10 messages, 100 Bytes, 5 revealed in proof", 1, 100, 1), null, 2));

console.log(JSON.stringify(generateTestVector("1 messages, 100 Bytes, 1 revealed in proof", 3, 10, 3), null, 2));
console.log(JSON.stringify(generateTestVector("1 messages, 100 Bytes, 1 revealed in proof", 1, 10, 1), null, 2));
console.log(JSON.stringify(generateTestVector("3 messages, 100 Bytes, 1 revealed in proof", 3, 10, 1), null, 2));

//console.log(JSON.stringify(generateTestVector("100 message, 100 Bytes, 25 revealed in proof", 100, 100, 25), null, 2));
