# Pushing this repository

This repo already has five commits on `master`. Nothing needs recreating.

## 1. Create an empty repo on GitHub

No README, no .gitignore, no licence — an empty repo, or the first push will conflict.

## 2. Push

```bash
unzip manet-beacon-trust.zip
cd manet-beacon-trust

git branch -M main
git remote add origin git@github.com:<you>/manet-beacon-trust.git   # or https://
git push -u origin main
```

## 3. Check the author on the commits

They were made with a placeholder identity. To rewrite them to yours before pushing:

```bash
git config user.name  "Your Name"
git config user.email "you@example.com"
git rebase -r --root --exec 'git commit --amend --no-edit --reset-author'
```

Do this *before* the first push, not after.
