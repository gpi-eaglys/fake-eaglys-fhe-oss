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


##  Pull PR branch to private
* in a localy work dir of private repo `fake-eaglys-tfhe.git`
* if a PR is opened in the OSS repo -> pull it into the private 

```
git fetch oss pull/<PR_NUMBER>/head:pr-<PR_NUMBER>
```
* for example for PR number **1** it would be:
```
git fetch oss pull/<PR_NUMBER>/head:pr-<PR_NUMBER>
# for example: 
git fetch oss pull/1/head:pr-1
```



