# [0.20.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.18.1...0.20.0) (2024-09-16)

### Build System

- **deps:** bump neon from 0.10.1 to 1.0.0 ([#239](https://github.com/mattrglobal/node-bbs-signatures/issues/239))
  ([45fa9c6](https://github.com/mattrglobal/node-bbs-signatures/commit/45fa9c638375c381a1e0a737a7722950abce8ed2))

### Features

- remove support for node 16
  ([45fa9c6](https://github.com/mattrglobal/node-bbs-signatures/commit/45fa9c638375c381a1e0a737a7722950abce8ed2))
- adds support for node 20 and 22
  ([45fa9c6](https://github.com/mattrglobal/node-bbs-signatures/commit/45fa9c638375c381a1e0a737a7722950abce8ed2))

### BREAKING CHANGES

- node 16.x no longer supported

# [0.19.0](https://github.com/mattrglobal/node-bbs-signatures/compare/v0.17.0...v0.19.0) (2024-07-04)

### Features

- remove support for node 14
  ([0f8c281](https://github.com/mattrglobal/node-bbs-signatures/commit/0f8c281c2fb0a00fba2aca54268576a05227ce92))

### BREAKING CHANGES

- node 14.x no longer supported

## [0.18.1](https://github.com/mattrglobal/node-bbs-signatures/compare/0.18.0...0.18.1) (2023-09-27)

### Bug Fixes

- adds missing build files for arm

# [0.18.0](https://github.com/mattrglobal/node-bbs-signatures/compare/v0.17.0...v0.18.0) (2023-09-26)

### Bug Fixes

- removes rayon feature from bbs crate
  ([7ab7ad4](https://github.com/mattrglobal/node-bbs-signatures/commit/7ab7ad474b5c0b996571a75af65850ea4cadaeab))

# [0.17.0](https://github.com/mattrglobal/node-bbs-signatures/compare/v0.16.0...v0.17.0) (2023-09-18)

### Bug Fixes

- publish unstable with node 18.x only
  ([81f7dca](https://github.com/mattrglobal/node-bbs-signatures/commit/81f7dcad22d5c5c1cf479aeb45b73e4dd12ab7a5))

# [0.16.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.15.0...0.16.0) (2023-09-17)

### Features

- add node 18 support
  ([6140f72](https://github.com/mattrglobal/node-bbs-signatures/commit/6140f72ba29034af82eb8395ccd8aac884450628))

# [0.15.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.14.0...0.15.0) (2022-07-11)

### Bug Fixes

- update bbs to 0.4.1 and run cargo update
  ([3ac291a](https://github.com/mattrglobal/node-bbs-signatures/commit/3ac291a557443c93ff061a188fdbdf267ef98d98))

# [0.14.0](https://github.com/mattrglobal/node-bbs-signatures/compare/v0.13.0...v0.14.0) (2022-06-23)

### Features

- upgrade dependencies
- adding github actions to backup repository to s3
  ([#188](https://github.com/mattrglobal/node-bbs-signatures/issues/188))
  ([93f5f41](https://github.com/mattrglobal/node-bbs-signatures/commit/93f5f41aa3921c3cf78ef001272d7eaad1b3c6fc))

# [0.13.0](https://github.com/mattrglobal/node-bbs-signatures/compare/v0.12.0...v0.13.0) (2021-11-30)

### Bug Fixes

- strict check for given messages count and originally revealed
  ([#175](https://github.com/mattrglobal/node-bbs-signatures/issues/175))
  ([b9679d4](https://github.com/mattrglobal/node-bbs-signatures/commit/b9679d448d7250c13468b9441e99a4010a6958f3))

# [0.12.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.11.0...0.12.0) (2021-05-21)

Add NodeJS version 15 and 16 support

### Bug Fixes

- benchmarks and add to gh action
  ([e1650e7](https://github.com/mattrglobal/node-bbs-signatures/commit/e1650e7e4cbfd6b2ad2a1894939548f08b1a4812))

# [0.11.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.10.0...0.11.0) (2020-11-23)

### Features

- change to async based api ([#136](https://github.com/mattrglobal/node-bbs-signatures/issues/136))
  ([92450c3](https://github.com/mattrglobal/node-bbs-signatures/commit/92450c34714f8039d222feb2106cc63701b4d42a))

### BREAKING CHANGES

- All API's now return a promise instead of the raw result

# [0.10.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.9.0...0.10.0) (2020-08-27)

### Bug Fixes

- native node module resolution ([#131](https://github.com/mattrglobal/node-bbs-signatures/issues/131))
  ([4cb57b7](https://github.com/mattrglobal/node-bbs-signatures/commit/4cb57b72b22243eb74394b74d1362ec06f509875))

### Features

- add blinded bls12-381 key generation ([#130](https://github.com/mattrglobal/node-bbs-signatures/issues/130))
  ([9b2646e](https://github.com/mattrglobal/node-bbs-signatures/commit/9b2646e3eb41b0fb4a46448c137b715e319dcc30))
- add bls12-381 g1 key generation support ([#127](https://github.com/mattrglobal/node-bbs-signatures/issues/127))
  ([85e89a0](https://github.com/mattrglobal/node-bbs-signatures/commit/85e89a02e6649d4c31b1c07d252267d48f9b9c73))

### BREAKING CHANGES

- generateBls12381KeyPair has been changed to generateBls12381G2KeyPair
- All operations involving messages and nonces are now in terms of Uint8Array's rather than strings

# [0.9.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.8.0...0.9.0) (2020-06-18)

### Features

- support building for node 13 and 14 ([#118](https://github.com/mattrglobal/node-bbs-signatures/issues/118))
  ([19be9e1](https://github.com/mattrglobal/node-bbs-signatures/commit/19be9e1d945c03fbd85830a969b370f222bf5203))
- update sample ([#112](https://github.com/mattrglobal/node-bbs-signatures/issues/112))
  ([3ff8c0f](https://github.com/mattrglobal/node-bbs-signatures/commit/3ff8c0f333e041a18c008799a064046535aebba5))

# [0.8.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.7.0...0.8.0) (2020-05-19)

### Features

- update to bbs 0.4.0 crate ([#109](https://github.com/mattrglobal/node-bbs-signatures/issues/109))
  ([c5f3a9c](https://github.com/mattrglobal/node-bbs-signatures/commit/c5f3a9c961beeb3165dbfb1982b4f5bb20fd18f9))

# [0.7.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.6.0...0.7.0) (2020-05-04)

- add support for publishing Node 11 and Node 12 binaries
  ([#100](https://github.com/mattrglobal/node-bbs-signatures/issues/100))
  ([eb9a667](https://github.com/mattrglobal/node-bbs-signatures/pull/104/commits/eb9a667e98a9bade59d874a5f91bcc862f130a32))
  ([f1af7ee](https://github.com/mattrglobal/node-bbs-signatures/pull/105/commits/f1af7eebc8561b43cea286426e744dbb8758a450))

# [0.6.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.5.0...0.6.0) (2020-05-03)

### Features

- add simple runnable sample ([#94](https://github.com/mattrglobal/node-bbs-signatures/issues/94))
  ([5b7acd4](https://github.com/mattrglobal/node-bbs-signatures/commit/5b7acd4092fec1e3cd459297fb74b11f7fa05079))
- update to bbs 0.3.0 crate
  ([c6f635e](https://github.com/mattrglobal/node-bbs-signatures/commit/c6f635e5c2734ee76d7a36ef3f7b26ba48d51d16))

# [0.5.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.3.0...0.5.0) (2020-04-28)

Updates to package release configuration

# [0.4.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.3.0...0.4.0) (2020-04-28)

Updates to package release configuration

# [0.3.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.1.0...0.3.0) (2020-04-28)

Version bump due to NPM package publishing issue caused by prior delete 0.2.0 release

# [0.2.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.1.0...0.2.0) (2020-04-28)

### Bug Fixes

- create proof with invalid message set ([#81](https://github.com/mattrglobal/node-bbs-signatures/issues/81))
  ([bf6453f](https://github.com/mattrglobal/node-bbs-signatures/commit/bf6453fe35369a837b47dadd4b484670bcd9f214))

# [0.1.0](https://github.com/mattrglobal/node-bbs-signatures/compare/0.2.0...0.1.0) (2020-04-26)

Initial release
