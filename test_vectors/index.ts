import { generateTestVector } from "./helper";

console.log("10 messages, 100 Bytes, 5 revealed in proof");
console.log(JSON.stringify(generateTestVector("10 messages, 100 Bytes, 5 revealed in proof", 10, 100, 5), null, 2));

console.log("1 message, 100 Bytes, 1 revealed in proof");
console.log(JSON.stringify(generateTestVector("1 messages, 100 Bytes, 1 revealed in proof", 10, 100, 5), null, 2));

console.log("100 message, 100 Bytes, 25 revealed in proof");
console.log(JSON.stringify(generateTestVector("100 message, 100 Bytes, 25 revealed in proof", 100, 100, 25), null, 2));