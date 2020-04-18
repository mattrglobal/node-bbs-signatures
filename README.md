# Node BBS Signatures

BBS+ Signatures are digital signature algorithm originally proposed by Camenisch et al. in
[Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited ](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited).

BBS+ signatures require a
[pairing-friendly curve](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03), this library includes
support for [BLS12-381](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-03#section-2.4).

BBS+ Signatures allow for multi-message signing whilst producing a single output signature. With a BBS signature, a
[proof of knowledge](https://en.wikipedia.org/wiki/Proof_of_knowledge) can be produced where only some of the originally
signed messages are revealed at the discretion of the prover.

For more details on the signature algorithm please refer to [here](./docs/ALGORITHM.md)

## Dependencies

This library uses the rusted based cryptographic implementation of BBS+ signatures and BLS12-381 from the
[Hyperledger Ursa Project](https://github.com/hyperledger/ursa), which is then wrapped and exposed in
javascript/typescript using [neon-bindings](https://github.com/neon-bindings/neon).

## Getting Started

The following describes how to get started as a contributor to this project

### Installation

With [Yarn](https://yarnpkg.com/) run:

```
yarn install --frozen-lockfile
yarn build
```

### Testing

With [Yarn] run:

```
yarn test
```

### Benchmarking

With [Yarn] run:

```
yarn benchmark
```

## Contributing

Read our [contributing guide](./docs/CONTRIBUTING.md) to learn about our development process.

## Relevant References

For those interested in more details, you might find the following resources helpful

- [BLS12-381 For The Rest Of Us](https://hackmd.io/@benjaminion/bls12-381)
- [Pairing-based cryptography](https://en.wikipedia.org/wiki/Pairing-based_cryptography)
- [Exploring Elliptic Curve Pairings](https://vitalik.ca/general/2017/01/14/exploring_ecp.html)
- [Anonymous Attestation Using the Strong Diffie Hellman Assumption Revisited](https://www.researchgate.net/publication/306347781_Anonymous_Attestation_Using_the_Strong_Diffie_Hellman_Assumption_Revisited)
- [Pairing Friendly Curves](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-01)
- [BLS Signatures](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02)
