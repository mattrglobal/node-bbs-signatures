import { generateTestVector } from "./helper";

console.log(JSON.stringify(generateTestVector("3 messages, 10 Bytes, 3 revealed in proof", 3, 10, 3), null, 2));
console.log(JSON.stringify(generateTestVector("1 messages, 10 Bytes, 1 revealed in proof", 1, 10, 1), null, 2));
console.log(JSON.stringify(generateTestVector("3 messages, 10 Bytes, 1 revealed in proof", 3, 10, 1), null, 2));
