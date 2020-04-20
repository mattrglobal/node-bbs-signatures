# Node BBS Signatures

![Master](https://github.com/mattrglobal/node-bbs-signatures/workflows/push-master/badge.svg)

This repository is the home to a performant multi-message digital signature algorithm which supports deriving zero knowledge proofs that enable selectively disclosure from the originally signed message set.

BBS+ Signatures are a digital signature algorithm originally born from the work on [Short group signatures](https://crypto.stanford.edu/~xb/crypto04a/groupsigs.pdf) by Boneh, Boyen, and Shachum which was later improved on in [Constant-Size Dynamic k-TAA](http://web.cs.iastate.edu/~wzhang/teach-552/ReadingList/552-14.pdf) as BBS+ and touched on again in section 4.3 in [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited ](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited).

BBS+ signatures require a [pairing-friendly curve](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03), this library includes support for [BLS12-381](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03#section-2.4).

BBS+ Signatures allow for multi-message signing whilst producing a single output signature. With a BBS signature, a [proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge) based proof can be produced where only some of the originally signed messages are revealed at the discretion of the prover.

For more details on the signature algorithm please refer to [here](./docs/ALGORITHM.md)

## Getting started

To use this package within your project simply run

```
npm install @mattrglobal/node-bbs-signatures
```

Or with [Yarn](https://yarnpkg.com/)

```
yarn add @mattrglobal/node-bbs-signatures
```

## Usage

The following is a short sample on how to use the API

```typescript
import { generateBls12381KeyPair, sign, verify, createProof, verifyProof } from "@mattrglobal/node-bbs-signatures";

//Generate a new key pair
const keyPair = generateBls12381KeyPair();

//Set of messages we wish to sign
const messages = [ "message1", "message2" ];

//Create the signature
const signature = sign({
    secretKey: keyPair.secretKey,
    domainSeparationTag: "domain",
    messages: messages,
});

//Verify the signature
const isVerified = verify({
    publicKey: keyPair.publicKey,
    domainSeparationTag: "domain",
    messages: messages,
    signature
});

//Derive a proof from the signature revealing the first message
const proof = createProof({
    signature,
    publicKey: keyPair.publicKey,
    messages,
    nonce: "nonce",
    domainSeparationTag: "domain",
    revealed: [0],
});

//Verify the created proof
const isProofVerified = verifyProof({
    proof,
    publicKey: keyPair.publicKey,
    messageCount: messages.length,
    messages,
    nonce: "nonce",
    domainSeparationTag: "domain",
    revealed: [0],
});
```

## Getting started as a contributor

The following describes how to get started as a contributor to this project

### Prerequisites

The following is a list of dependencies you must install to build and contribute to this project

- [Yarn](https://yarnpkg.com/)
- [Rust](https://www.rust-lang.org/)

#### Install

To install the package dependencies run:

```
yarn install --frozen-lockfile
```

#### Build

To build the project run:

```
yarn build
```

#### Test

To run the test in the project run:

```
yarn test
```

#### Benchmark

To benchmark the implementation locally run:

```
yarn benchmark
```

## Dependencies

This library uses the rust crate  of BBS+ signatures and BLS12-381 from the [Hyperledger Ursa Project](https://github.com/hyperledger/ursa), which is then wrapped and exposed in javascript/typescript using [neon-bindings](https://github.com/neon-bindings/neon).

## Relevant References

For those interested in more details, you might find the following resources helpful

- [Details on the algorithm](docs/ALGORITHM.md)
- [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)
- [Pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography)
- [Exploring Elliptic Curve Pairings](https://vitalik.ca/general/2017/01/14/exploring_ecp.html)
- [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited)
- [Pairing Friendly Curves](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-01)
- [BLS Signatures](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02)
