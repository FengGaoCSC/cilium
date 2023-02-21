---
name: Create a new stable enterprise branch (v1.X-ce)
about: A checklist for initialization of the enterprise-only bits for a new stable branch
title: 'v1.X-ce branch initialization'
assignees: ''
---

_If you need help: ask in #enterprise-release._

After OSS has created a new stable branch (say, [v1.13]), it's time to also
create the corresponding enterprise branch, and initialize it with all the magic
sprinkles that make up the enterprise edition.

On a high level, we need to introduce the [atlantis] configuration, adjust CI
to now care about `-ce` branches and add some automation details. 

## Prepare the branch

- [ ] Create a PR that updates the `.github/workflows/mirror-upstream.yaml`
      file to also include the new `v1.X`, so that the Isovalent fork also
      mirrors the new branch:
  - [ ] Add the "v1.X" to the [`BRANCHES`]
  - [ ] Potentially extend the [`PATHSPEC`] of mirrored CI workflows. A
        `grep issue_comment ./.github/workflows/* -R -l` on
        `cilium/cilium` gives you the list.
- [ ] Once merged, trigger the workflow.
- [ ] Create the new enterprise branch, i.e. `git switch` to the new branch,
      then `git branch v1.XX-ce`. Push it to the fork.

(We don't add the things below directly at this point so that there's a chance
to do review on a PR.)

## Add Atlantis

- [ ] Add atlantis:
  - [ ] Add the `atlantis.yaml` file, which you can typically copy from the
        last stable branch to have a template, and then figure out which
        versions you should be pulling in (typically the latest released ones).
  - [ ] Run `atlantis gen` as part of the CI/Release/Hotfix builds, by adding
        jobs to the github workflows. For inspiration, look at [this PR for
        v1.13]. (Things might have moved around a fair bit, don't just blindly
        copy.)

Note that at this point some of the atlantis plugins might not be compatible
with the new OSS code structure. Disable them, and notify people on Slack that
this incompatibility exists. It's more important to get the branch initialized
than to have it be perfect from the get-go, as not having this branch blocks
forward porting work of enterprise-only features. Don't forget to get all the
plugins enabled again before shipping a release, though! :ship:

## CI and Makefiles

- [ ] Change all references to `1.X` to `1.X-ce` in
      `.github/workflows/build-image-*.yaml`, for inspiration again see [this PR
      for v1.13].
- [ ] Add the enterprise variants of the Makefile definitions:
  - [ ] `install/kubernetes/Makefile.enterprise.values`: Base it on the OSS
        `Makefile.values`, but replace the image registries with their Isovalent
        counterparts, i.e. `quay.io/cilium` becomes `quay.io/isovalent` or
        `quay.io/isovalent-dev` as appropriate. See [this diff] for reference.
  - [ ] `install/kubernetes/Makefile.enterprise.digests` is just a copy of the
        OSS variant.
  - [ ] Change `install/kubernetes/Makefile` so that `MAKEFILE_VALUES` points to
        the newly created `Makefile.enterprise.values`.

## Forward port Workflows with pull_request targets

Most of the GitHub workflow definitions can live in the `default` branch, but
stuff which should run when on a `pull_request` trigger needs to be in the
base/target branch of a PR for GitHub to consider it. Workflows which are not in
OSS thus need to be forward ported from the last stable enterprise branch.
Here's a likely not exhaustive list of what needs to come with:

- [ ] `close-fixed-issues.yaml`: You need to change the `branches` in the `on`
      section to match the new branch name.


[v1.13]: https://github.com/cilium/cilium/tree/v1.13
[atlantis]: https://github.com/isovalent/atlantis/
[this diff]: https://github.com/isovalent/cilium/pull/746#issuecomment-1437703837
[this PR for v1.13]: https://github.com/isovalent/cilium/pull/574
[`BRANCHES`]: https://github.com/isovalent/cilium/blob/db3697989ca5224b246e358867107cc28c3d25ba/.github/workflows/mirror-upstream.yaml#L28
[`PATHSPEC`]: https://github.com/isovalent/cilium/blob/db3697989ca5224b246e358867107cc28c3d25ba/.github/workflows/mirror-upstream.yaml#L65
