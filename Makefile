.PHONY: generate build build-debug

DLVBINARY=$(shell which dlv)

BUILDFLAG=

TESTNS=test
VETHHOSTNAME=veth-host
VETHNSNAME=veth-ns
VETHHOSTIP=198.19.20.21/30
VETHNSIP=198.19.20.22/30
TUNNELSERVER=http://198.19.20.21


generate:
	go generate ./...

build-debug: BUILDFLAG="-gcflags=all=-N -l"
build-debug: build

build-web:
	cd web && npm run build

build: generate build-web
	go build ${BUILDFLAG} -o bin/gateway ./cmd/gateway
	go build ${BUILDFLAG} -o bin/tunnel-server ./cmd/tunnel-server
	go build ${BUILDFLAG} -o bin/tunnel-client ./cmd/tunnel-client

fmt:
	go fmt ./...

vet:
	go vet ./...

testns: 
	sudo ip netns add ${TESTNS}
	sudo ip link add ${VETHHOSTNAME} type veth peer ${VETHNSNAME}
	sudo ip link set up dev ${VETHHOSTNAME} 
	sudo ip a add ${VETHHOSTIP} dev ${VETHHOSTNAME} 
	sudo ip link set netns ${TESTNS} dev ${VETHNSNAME} 
	sudo ip netns exec ${TESTNS} ip link set up dev ${VETHNSNAME}
	sudo ip netns exec ${TESTNS} ip link set up dev lo
	sudo ip netns exec ${TESTNS} ip addr add ${VETHNSIP} dev ${VETHNSNAME}

clear-testns:
	sudo ip netns del ${TESTNS}
	sudo ip link del ${VETHHOSTNAME}

run-tunnel-client-debug:
	sudo ip netns exec ${TESTNS} env DEBUG_ADDR=":12080" $(DLVBINARY) exec ./bin/tunnel-client --headless --listen=:2345 --api-version=2  -- --url=${TUNNELSERVER}