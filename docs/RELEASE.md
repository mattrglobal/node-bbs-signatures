## Unstable Releases

Each time a push to master is made, the `push-master` workflow will run which automatically creates an unstable release
and pushes this to the github package manager.

### Manual Release

If the automated unstable release fails, please run the following manually

1. Checkout the head of master `git checkout master && git pull`
2. Run `npm login --registry=https://npm.pkg.github.com` and follow the prompts outlined below.
   1. Enter your github username
   2. Generate a [personal access token](https://github.com/settings/tokens) with `read:packages` and `write:packages`
      permissions
   3. Enter the generated personal access token as the password
   4. Enter your github email
3. Ensure the package is clean from previous branches/builds `yarn clean`
4. Install the dependencies `yarn install`
5. Build the package `yarn build`
6. Publish the package `yarn publish:unstable`
7. Observe the newly created unstable packages in the github package manager.

**Note** - Yarn cannot be used in step 2 as it does not support the `--registry` flag
