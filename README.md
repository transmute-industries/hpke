# @transmute/hpke

[![CI](https://github.com/transmute-industries/hpke/actions/workflows/ci.yml/badge.svg)](https://github.com/transmute-industries/hpke/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@transmute/hpke.png?mini=true)](https://npmjs.org/package/@transmute/hpke) -->

🚧 Experimental 🔥

This is yet another HPKE implementation for JOSE and COSE.

The purpose of this experimental implementation is to address open questions regarding the IETF drafts.

- [x] Integrated Encryption - how is it signaled in JOSE and COSE, what values are used for "alg" and "enc".
- [ ] Party U / Party V - identity information in key establishment.
- [ ] Cross Mode Attacks - How are they mitigated in COSE and JOSE?

