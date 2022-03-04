# NTRU-tmvp4-m4

This code accompanies the paper "Faster NTRU on ARM Cortex-M4 with TMVP-based multiplication".

This repository contains our TMVP-based implementations for ntruhps2048509 and ntruhrss701 for Cortex-M4.

Please clone this repository recursively to include [libopencm3](http://libopencm3.org/).
```
    git clone --recursive https://github.com/NTRU-tmvp4-m4/NTRU-tmvp4-m4
```

To run all benchmarks for all schemes run `benchmarks.py`.

You can build binaries by running
`make IMPLEMENTATION_PATH=crypto_kem/{scheme}/{implementation} bin/crypto_kem_{scheme}_{implementation}_{test}.bin`

E.g., `make IMPLEMENTATION_PATH=crypto_kem/ntruhps4096821/tmvp bin/crypto_kem_ntruhps4096821_tmvp_speed.bin`

To flash the binaries to the board, and to receive and print the output from the board run `read_guest.py {binary}`.


Most parts of the codes in this repository are taken from [this one](https://github.com/ntt-polymul/ntt-polymul).