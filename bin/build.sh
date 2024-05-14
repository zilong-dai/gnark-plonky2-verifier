#!/bin/bash

go build -o libg16verifier.so -buildmode=c-shared main.go
go build -o libg16verifier.a -buildmode=c-archive main.go
