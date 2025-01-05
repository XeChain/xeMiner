# xeMiner

Open source [xehash](https://github.com/XeChain/xehash-go) miner in Go forked from [xMiner](https://github.com/CyberChainXyz/xMiner) with [stratum-jsonrpc2.0-ws](https://github.com/CyberChainXyz/stratum-jsonrpc2-ws) protocol.

The OpenCL kernel code originates from [xmr-stak](https://github.com/fireice-uk/xmr-stak/tree/master/xmrstak/backend).

## Download

You can download the pre-built binaries from our **Releases** page. Choose the appropriate version for your operating system.

## Performance Testing

```bash
./xeMiner -mock -all
```

## Show OpenCL devices informations

```bash
./xeMiner -info -all
```

This will display all available OpenCL devices with their indices:
```
Available OpenCL devices:
[1] NVIDIA GeForce RTX 3080 (Vendor: NVIDIA Corporation)
[2] AMD Radeon RX 6800 (Vendor: Advanced Micro Devices)
...
```

## Device Selection

You can choose specific devices to mine with using the `-devices` or `-d` flag:

```bash
# Use specific devices (e.g., devices 1 and 3)
./xeMiner -devices "1,3"
# or use the short option
./xeMiner -d 1,3

# Use all available devices (default behavior)
./xeMiner
```

## Solo mining

**Run a xeChain client with mining feature enabled**
```
./xe -ws -mine -miner.etherbase=0x123...fff
```
Replace 0x123...fff with your own address.

**Run the miner**
```bash
./xeMiner
```
The default pool address is ws://127.0.0.1:8546.

## Pool Mining
```bash
./xeMiner -user=username -pass=password -pool=wss://pool-address.com:port
```
Replace `user, pass, pool` with your actual values provided by the mining pool.

## Compile from source

**Requirements**

linux
```bash
sudo apt install ocl-icd-opencl-dev opencl-headers
```

**Clone the repository and build the miner**
```bash
git clone https://github.com/XeChain/xeMiner
cd xeMiner
go build .
```
