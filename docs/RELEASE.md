## Unstable Releases

Each time a push to master is made, the `push-master` workflow will run which automatically creates an unstable release and pushes this to the github package manager.

### Manual Release

If the automated unstable release fails, please run the following manually

1. Create an unstable release branch from the head of master
2. Run `npm login --registry=https://npm.pkg.github.com` and follow the prompts outlined below.
**Note** - Yarn cannot be used in the above step as it does not support the `--registry` flag
    1. Enter your github username
    2. Generate a [personal access token](https://github.com/settings/tokens) with `read:packages` and `write:packages` permissions
    3. Enter the generated personal access token as the password
    4. Enter your github email
3. Run `yarn publish:unstable`
4. Observe the newly created unstable packages in the github package manager
5. Observe the newly created commit on your branch with commit message `chore(release): new unstable [skip ci]`
6. Push the commit to your unstable release branch, be sure to include tags with `git push --tags`.
7. Open a pull request for the un-stable release.