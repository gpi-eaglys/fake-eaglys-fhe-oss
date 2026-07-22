# Fake Eagly-TFHE 

* fake repo to test (a) private -> OSS and (b) OSS -> private workflows
  * `fake-eaglys-tfhe`  private repo (this repo)
  *  [fake-eaglys-tfhe-oss.git](https://github.com/gpi-eaglys/fake-eaglys-tfhe-oss.git)  OSS repo (not this repo
* private: 
  * only internal members can edit this repo 
  * some parts of source code/documentation is not public -> e.g., files under `internal`
  * repo history (internal PRs, branches) is NOT public

```
fake-eaglys-tfhe
├── internal
│   └── src
└── src
    ├── cndarray
    ├── high
    └── low
        ├── ...
        └── torus_polynomial
```



# Private -> OSS 
## Setup: actions 
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


# OSS -> Private

## Add OSS as a remote to private repo
* in a localy work dir of private repo `fake-eaglys-tfhe.git`
* add OSS repo as remote branch `oss` 
```
git remote add oss git@github.com:YOUR_USERNAME/fake-eaglys-tfhe-oss.git
git fetch oss
``` 

* if there seems to be a PR! 
```
$ git fetch oss
Unpacking objects: 100% (86/86), 57.40 KiB | 288.00 KiB/s, done.
From github.com:gpi-eaglys/fake-eaglys-tfhe-oss
 * [new branch]      feat/oss-pr1 -> oss/feat/oss-pr1
 * [new branch]      main         -> oss/main
```
* open GitHub and check pull request
  * first PR arrive: `https://github.com/gpi-eaglys/fake-eaglys-tfhe-oss/pull/1`



##  Pull PR branch to private repo
* in a localy work dir of private repo `fake-eaglys-tfhe.git`
* if a PR is opened in the OSS repo -> pull it into the private 
* check it's serial number: e.g., `pull/1` -> `1` 

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

##  Treat OSS PR branch as a private PR 

* modify, adapt source code
* create PR local to private repo
* merge PR -> will trigger sync with OSS repo


##  Close OSS PR -> add courtesy note
* on the OSS PR page -> close the PR
* give credit to the author of the OSS PR 
* unfortunatly the OSS repo will not track the original authors in git history

```
Thank you Dude for your contribution! 
Your PR was merged internally as <commit-sha> — and will appear in this repo automatically!
```













