#!/usr/bin/env bats
# Copyright (c) 2019 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Plum


@test "acpack" {
  acpack build --os windows --arch 386 --debug
  cd acpack
  ./artifactcollector
  unzip *.forensicstore -d store
  mkdir store/my.store
  mv store/*.forensicstore/* store/my.store
  forensicstore validate store/my.store
}

#- name: Pack
#  run: |
#    cd acpack
#    ls
#    cp ../test/pack/ac.yaml .
#    cp -r ../test/pack/artifacts/ artifacts
#    cp -r ../test/pack/bin binaries
#    mkdir plugins src
#    cp -r ../artifactcollector src/artifactcollector
#    rm -rf src/artifactcollector/pack/*
#    cp -r ../goflatten src/goflatten
#    cp -r ../goforensicstore src/goforensicstore
#    cp -r ../gojsonlite src/gojsonlite
#    cp -r ../forensicartifacts src/forensicartifacts
#    cp -r ../fslib src/fslib
#    cp -r ../go.mod src/go.mod
#    cp -r ../go.sum src/go.sum
#    mv dist/linux/acpack acpack
#    ./acpack build --os windows --arch amd64 --debug
#    ./acpack build --os windows --arch 386 --debug
