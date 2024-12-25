# File sharing service in Golang

This repository contains the code for a file sharing service that guarantees integrity and confidentiality while supporting functions for user creation and authentication, file creation, modification, and deletion, and sharing and revoking permissions. The service is written in Golang. 

The design of this project is based on the requirements for the spec provided here: https://cs161.org/proj2/ . The functions for this service use calls to an API to store and load data from the proper databases.

The implementation code is provided in `client/client.go`. Integration tests are located in `client_test/client_test.go`, and unit tests are located in `client/client_unittest.go`. 

To test, run `go test -v` inside of the `client_test` directory. This will run all tests in both `client/client_unittest.go` and `client_test/client_test.go`.
