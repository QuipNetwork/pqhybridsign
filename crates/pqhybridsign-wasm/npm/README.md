# Publishing this package

`package.json` here is a template: it declares the package's name, exports
and files, but the `web/` and `node/` directories it points at are build
output, not checked into git. To produce a publishable package:

```sh
../scripts/build-npm.sh   # writes npm/web/ and npm/node/
npm publish               # run from this directory
```

`scripts/check-types.sh` (run from the crate root, and wired into
continuous integration) regenerates the TypeScript definitions and fails
if they differ from the checked-in copies under `types/`. Run
`scripts/regenerate-types.sh` and commit the result whenever
`src/lib.rs`'s public surface changes.
