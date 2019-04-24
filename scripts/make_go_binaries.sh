#!/bin/bash -xv

# Author: evuraan@gmail.com

mkdir -pv ../bin/
	
go get golang.org/x/net/dns/dnsmessage && {
	GOOS=linux GOARCH=arm GOARM=7 go build  -o ../bin/magan-go-linux-armv7l ../src/magan_go.go
	GOOS=linux GOARCH=arm GOARM=6 go build  -o ../bin/magan-go-linux-armv6l ../src/magan_go.go
	GOOS=windows GOARCH=amd64 go build -o ../bin/magan-go-win-amd64.exe ../src/magan_go.go
	GOOS=windows GOARCH=386 go build -o ../bin/magan-go-win-386.exe ../src/magan_go.go
	GOOS=linux GOARCH=amd64 go build -o ../bin/magan-go-linux-amd64 ../src/magan_go.go
	GOOS=linux GOARCH=386 go build -o ../bin/magan-go-linux-386 ../src/magan_go.go
}
