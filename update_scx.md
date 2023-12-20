# 本地代码和scx官方仓库同步

git fetch origin：拉取远程分支

git checkout main：因为本地是main分支，所以要切换到它

git merge origin/sched_ext：合并且保留main中已有的更改，此时会要求填写合并的原因。注意要小心运行这个操作，否则很可能会把错误的代码合并进去

如果有冲突则需要添加更改到暂存区：git add .，然后继续完成合并：git commit

## 查看两个分支的差异

git diff main origin/sched_ext：查看两个分支最后一次提交的差异，可以查看所有更改，内容比较多

git diff main origin/sched_ext -- [file_path]：查看特定文件的差异

git diff main origin/sched_ext | less：通过分页查看更改结果，包括新增、修改、删除的行

# 本地代码和自己的备份库同步

git remote add L_sched_ext git@github.com:L-811/L_sched_ext.git：添加自己备份库的git引用

git push L_sched_ext sched_ext：将本地仓库中的内容推送到备份库
