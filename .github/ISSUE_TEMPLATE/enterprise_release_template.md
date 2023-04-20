---
name: Release a new version of Cilium Enterprise vX.Y.Z-cee.1
about: Create a checklist for an upcoming OSS-derived release
title: 'vX.Y.Z-cee.1 release'
labels: kind/release
assignees: ''

---

_WIP, derived from [The OG Cilium Enterprise release resource]_

_Tip of the day: Create a release using [this handy bash function]!_

_If you need help: ask in #enterprise-release._

## Prepare images

- [ ] Check whether we should make a corresponding Cilium OSS release first
  - Coordinate with the OSS release manager. They will have performed their
    release ritual but held off tagging until our release is ready as well.
- [ ] Synchronize the Isovalent tree to the upstream tree
  - Click the Run workflow button here: [mirror-upstream-workflow]
- [ ] Cherry-pick commits from the upstream tree since the last sync. You will
      have to determine the commit hash of the commit the OSS release will tag.
      Either check the `cilium/cilium` repo or use something like:
      `git fetch upstream && git log upstream/vX.Y --grep "release vX.Y.Z"`
      assuming that `upstream` points to `cilium/cilium`.

        # You need to tweak these three parameters.
        OSS_RELEASE_COMMIT_SHA=YOU_NEED_TO_FIND_THIS_YOURSELF
        VERSION=1.1x
        PR=pr/$USER/vX.Y.Z-prep

        # You can just copy & paste the rest.
        OSS_SYNC_TAG=oss-sync-${VERSION}-$(date +%Y-%m-%d)
        OSS_BRANCH=v${VERSION}
        CEE_BRANCH=v${VERSION}-ce
        LAST_OSS_COMMIT_SYNCED=$(git tag --sort=-creatordate | grep oss-sync-${VERSION} -m1)
        git fetch origin
        git fetch origin ${OSS_BRANCH}:${OSS_BRANCH}
        git fetch origin ${CEE_BRANCH}:${CEE_BRANCH}
        git checkout -B ${PR} ${CEE_BRANCH}
        git tag -m ${OSS_SYNC_TAG} ${OSS_SYNC_TAG} ${OSS_RELEASE_COMMIT_SHA}
        git cherry-pick --signoff ${LAST_OSS_COMMIT_SYNCED}..${OSS_RELEASE_COMMIT_SHA}

  - [ ] Resolve all conflicts that come up.
    - First conflict is typically in the "image digests" commit. For this one,
      we can mostly ignore the upstream changes; Cilium-CEE has its own
      different digests.
      - [ ] `git checkout --ours install/`
      - [ ] `git add install/`
      - [ ] `git cherry-pick --continue`
      - For `>=v1.11-ce` you'll encounter this in `Documentation` also, you can
        equally discard these.
    - Subsequent conflicts may require more indepth manual resolution.
      - Sometimes, we may have already backported the change; can `git cherry-pick --skip`.
      - Sometimes, there may be minor conflicts in files that contain versions.
      - If the conflict is surprising or unclear, raise a Slack thread with the
        relevant authors to make sure that the backport is correctly resolved.
      - [ ] `git cherry-pick --continue`
    - Final commit to cherry-pick has the message `Prepare for release vX.Y.Z`
      - Manually amend this commit to update:
        - [ ] `VERSION` file
        - [ ] `git checkout --ours install/kubernetes/cilium/{Chart.yaml,README.md,values.yaml}`
        - [ ] `make -C install/kubernetes`
          - [ ] for `>=v1.11-ce` run `make MAKEFILE_VALUES=Makefile.enterprise.values cilium/values.yaml`
                and make sure the values.yaml points to the correct image tags.
          - [ ] for `>=v1.11-ce` run `make -C Documentation update-helm-values`
        - [ ] `git diff` and manually inspect that all of the changes make sense
              in the Cilium Enterprise tree. Digests will be removed (e.g. in
              `install/kubernetes/cilium/README`), the quay.io repositories will
              change to Isovalent, and the versions should have the `-cee.1`
              suffix.
        - [ ] `git cherry-pick --continue`
        - [ ] Update the commit message to reflect the correct enterprise version `vX.Y.Z-cee.1`
- [ ] Open a pull request with this branch against the Isovalent repository
  - `gh pr create -B v1.X-ce` (NOTE: Make sure this is against Isovalent tree!)
  - [ ] Wait for CI images to build+push
  - [ ] Run end-to-end CI tests by posting a comment `/test-backport-1.X`
- [ ] Merge the PR. Then push the new OSS sync tag:

        git push origin ${OSS_SYNC_TAG}

- [ ] Deploy the CI image from `v1.X-ce` branch to alpo-2. If you are not sure how
      to do it, ask in #dogfooding Slack channel. There are a lot of helpful people
      in that channel. Note that only one branch can be deployed to alpo-2, so if
      you are preparing multiple releases, do this step only once.
- [ ] Tag the release
  - [ ] `git fetch origin`
  - [ ] `git checkout origin/v1.X-ce`
  - [ ] `git tag vX.Y.Z-cee.1 && git push origin vX.Y.Z-cee.1`
- [ ] Create a GH release: https://github.com/isovalent/cilium/releases

## Prepare Helm & documentation

_Handy tip: If you ever feel unsure, you can always look at how the previous
release was done. You'll see useful example PRs, and you can ask the previous
release manager if something remains unclear or you need a review._

- [ ] Wait for the images to build at [build-images-releases] workflow
  - You can check quay.io whether the images matching your tag have appeared:
    [quay-agent], [quay-operator]
  - [ ] This workflow also generates the `vX.Y.Z-cee.1-gen-tag` tag, which
        includes the generated code. Verify that the tag is created. If it
        isn't, for some reason, you can use the `atlantis-gen` workflow to
        generate it.
- [ ] Build the helm charts for the release via [helm-repo] workflow. You can
      check whether they were picked up with:

        helm repo add isovalent https://helm.isovalent.com
        helm repo update
        helm search repo isovalent/cilium --versions | grep X.Y.Y

- [ ] Update the "umbrella" [helm-charts]
  - Update `Chart.yaml`, and then run `test.sh`. Your PR should
    target `main` for the latest cilium version, and the `vX.Y` branch
    otherwise. 
  - Example PR: https://github.com/isovalent/helm-charts/pull/302/files
  - [ ] Merge the PR
  - [ ] Create a release: https://github.com/isovalent/helm-charts/releases/new
    - You can use Github's 'tag on publish' feature: Enter your desired tag in
      the tag field of the form (it should say something like 'create tag on
      publish'). Make sure you select the same branch you merged your PR into.
- [ ] Update the version in the cilium enterprise docs.
  - If you are releasing the very first (non-beta) enterprise release for a
    minor version, you will have to create a new branch in the enterprise docs
    repo. The enterprise docs are structured so that the latest version is on
    the `main` branch, and older releases on `X.Y` branches. Example: If
    `1.12.3` is the latest OSS version, and so far only 1.12.2-cee.beta1 has
    been released, you'll have to create a branch `1.11` off `main` to release
    `1.12.3-cee.1`.
  - [ ] Create a PR which updates the toplevel VERSION file to your newly
    released version. Target the PR at the `X.Y` branch. If there is no such
    branch, and you are releasing the latest minor, target `main`. 
- [ ] Prepare artifacts for Azure Marketplace build
  - Only one release is currently supported on Azure Marketplace. The release
    series is listed in the `CILIUM_VERSION` file in [Azure Marketplace CNAB].
    Ignore these steps if the 1.X versions do not match.
  - [ ] Create a PR for the [Azure Marketplace CNAB] repository to update the
        `CILIUM_VERSION` to match this new patch release version.
  - [ ] Notify CNAB owners to review & approve the build. Merge the PR.
  - [ ] Create a new tag on this repository with a new CNAB version.
    - Currently the version scheme for CNABs is `0.0.X`. The new tag would be
      `0.0.Y`, with `Y` being calculated as `X + 1`.
    - [ ] Create a release for the new tag
  - [ ] Create a Slack message in [#azure-partnership-internal] that the new
        version is being published. Reference the Cilium version and the newly
	created git tag. CC Christian Kuun.
- [ ] [only for the latest minor!] Using the cilium GH release notes, prepare
    release notes in the [cilium-enterprise-docs] against the main branch.
  - You'll need to look through the generated release notes in
    `isovalent/cilium` and expand the backport PRs (which usually contain
    multiple upstream PRs) into release notes. The upstream PR titles should
    work well.
  - The release note PR targets main, but contains release notes for all
    versions you are releasing. (Otherwise, the release notes for previous
    minors would be buried under docs.isovalent/vX.Y/ and not visible on
    toplevel.)
  - Example PR: https://github.com/isovalent/cilium-enterprise-docs/pull/748
    though do note that this PR should have also included release notes for
    `1.12.{0,1,2}-cee.beta1` since `1.12.3-cee.1` was the first stable CEE
    release of the `1.12` series.
  - [ ] Merge the PR
- [ ] Review [`Next Release` customer support tickets]. If this release fixes the issue, move the status
      from `Next Release` to `Fix Ready` and change assignee to the designated solutions architect.
- [ ] Update isogo.to/releases
  - [ ] Move the entry for the current release from planned to past.
  - [ ] Add an entry for the next release and its planned date.
- [ ] Announce release in [#release-announce](https://app.slack.com/client/T40ANG0TH/C043UEUA12T)

[Azure Marketplace CNAB]: https://github.com/isovalent/external-azure-marketplace-cnab
[#azure-partnership-internal]: https://isovalent.slack.com/archives/C0354JHPVT7
[build-images-releases]: https://github.com/isovalent/cilium/actions/workflows/build-images-releases.yaml
[cilium-enterprise-docs]: https://github.com/isovalent/cilium-enterprise-docs
[helm-charts]: https://github.com/isovalent/helm-charts
[helm-repo]: https://github.com/isovalent/helm-repo/actions/workflows/generate.yaml
[mirror-upstream-workflow]: https://github.com/isovalent/cilium/actions/workflows/mirror-upstream.yaml
[The OG Cilium Enterprise release resource]: https://docs.google.com/document/d/1-VNR7IwdQecWCtIiEChvfvUyit-kkRt-LVkavIDjHDU/edit
[this handy bash function]: https://github.com/isovalent/cilium/blob/default/create_release_issues.bash
[`Next Release` customer support tickets]: https://github.com/orgs/isovalent/projects/9/views/11
[quay-agent]: https://quay.io/repository/isovalent/cilium?tab=tags&tag=latest
[quay-operator]: https://quay.io/repository/isovalent/operator?tab=tags&tag=latest
