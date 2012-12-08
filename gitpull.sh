#!/bin/sh
# http://stackoverflow.com/questions/5828324/update-git-submodule
# pull root and subprojects
git pull
for dir in src/be13_api 
do
  pushd $dir
  git checkout master
  git pull
  popd
done
