<<<<<<< HEAD
# Fake Eagly-TFHE 

* fake repo to test (a) private -> OSS and (b) OSS -> private workflows
  * `fake-eaglys-tfhe`  private repo (this repo)
  *  [fake-eaglys-tfhe-oss.git](https://github.com/gpi-eaglys/fake-eaglys-tfhe-oss.git)  OSS repo (not this repo
* private repo: 
  * only internal members can edit this repo 
  * some parts of source code/documentation is not public -> e.g., files under `internal`
  * repo history (internal PRs, branches) is NOT public

```
fake-eaglys-tfhe
├── github/workflows
│   └── internal-sync-to-oss.yml  # filtered out for OSS
├── internal                      # filtered out for OSS
│   └── src
└── src
    ├── cndarray
    ├── high
    └── low
        ├── ...
        └── torus_polynomial
```

* OSS repo:
   * public GitHub repository 
   * anyone can create PR


## Overview 

![gitflow-overview](docs/pix/git-flow-overview.png)


# Private-to-OSS Sync

## Setup: GitHub Actions 
* sync to OSS is triggered automatically by CI/CD
   * trigger: a PR merged to `main` branch 
   * a simple push to `main` does NOT trigger sync
   * there is no sync script -> cannot be triggered manually
* the sync process is implemented as a GitHub action

## Setup: Deploy key

### Generete deploy key pair 
  * use dedicated user for this task, e.g., `sync-bot`
  * produces: (a) `sync_deploy_key` and (b) `sync_deploy_key.pub`

```
ssh-keygen -t ed25519 -C "sync-bot" -f sync_deploy_key -N ""
```

###  Private key: add to private repo
* open GitHub repo: `fake-eaglys-tfhe` 
* **Settings -> Secrets and veriables -> Actions -> New**
* paste contents of `sync_deploy_key`


###  Public key: add to OSS repo
* open GitHub repo: `fake-eaglys-tfhe-oss` 
* **Settings -> Deploy keys -> Add deploy key**
* paste contents of `sync_deploy_key.pub`



# OSS-to-Private Sync

## Add OSS as a remote origin to the private repo
* in a localy workdir of private repo `fake-eaglys-tfhe.git`
* add OSS repo as remote branch `oss` 
```
git remote add oss git@github.com:YOUR_USERNAME/fake-eaglys-tfhe-oss.git
git fetch oss
``` 

* if there is PR in the OSS repo 
  * do not work on the PR on the OSS repo
  * pull the PR into the private repo
```
$ git fetch oss
Unpacking objects: 100% (86/86), 57.40 KiB | 288.00 KiB/s, done.
From github.com:gpi-eaglys/fake-eaglys-tfhe-oss
 * [new branch]      feat/oss-pr1 -> oss/feat/oss-pr1
 * [new branch]      main         -> oss/main
```

* open PR on GitHub -> check pull request URL -> check PR serial number (below: `1`) 
```
https://github.com/gpi-eaglys/fake-eaglys-tfhe-oss/pull/1
```


##  Pull PR branch to private repo
* in a localy work dir of private repo `fake-eaglys-tfhe.git`
* if a PR is opened in the OSS repo -> pull it into the private repo
* check PR's serial number: e.g., `pull/1` -> `1` 
* locally name the PR e.g., `oss-pr-<PR_NUM>`

```
$ git fetch oss pull/<PR_NUM>/head:oss-pr-<PR_NUM>
```
* in case `PR_NUM=1` -> fetches onto `oss-pr-1`

```
$ git fetch oss pull/1/head:oss-pr-1
From github.com:gpi-eaglys/fake-eaglys-tfhe-oss
 * [new ref]         refs/pull/1/head -> oss-pr-1
kinoko@LPC-0081:~/GIT/eaglys/fake-eaglys-tfhe$ git branch -a
* main
  oss-pr-1                    <-   OSS pull request!!!
```

##  Update PR branch to private repo
* cannot repeat the fetch command above: `git fetch oss pull...` -> will error out
* force-update is possible with `+pull`
```
git fetch oss +pull/1/head:oss-pr-1
```
* check PR commit hash - using the local branch name
```
git rev-parse oss-pr-1
```

##  Create staging branch in private repo 
* a staging branch needs to be created 
* in order to fix issues or remove unnecessary changes
* naming
   * preserve original name 
   * sill convey that this is a staging branch

```
git checkout main
git pull origin main
git checkout -b extern/oss-pr-1     
``` 

* do NOT use `merge` but `cherry-pick`

```
git cherry-pick oss-pr-1
```

* this will introduce some errors
* fix conflicts manually 

```
git cherry-pick --continue
```

* push 
```
git push -u origin extern/oss-pr-1
``` 


##  Create PR in private repo from OSS PR branch 
* create PR local to private repo
* continue modifying this branch
* merge PR -> will trigger sync with OSS repo


##  Close OSS PR -> add courtesy note
* on the OSS PR page -> close the PR
* give credit to the author of the OSS PR 
* unfortunatly the OSS repo will not track the original authors in git history

```
Thank you Dude for your contribution! 
Your PR was merged internally as <commit-sha> — and will appear in this repo automatically!
```


2 directories, 1 file
=======
# fake-eaglys-tfhe
>>>>>>> 145b277 (Initial commit)
