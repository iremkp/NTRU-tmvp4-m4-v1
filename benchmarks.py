#!/usr/bin/env python3

import datetime
import subprocess
import sys

import serial
import numpy as np
from config import Settings


def toMacro(name, value, k=None):
  if value > 20000:
    value = f"{round(value/1000):,}k"
  else:
    value = f"{value:,}"
  value = value.replace(",", "\\,")
  return f"\\newcommand{{\\{name}}}{{{value}}}\n"

def run_bench(scheme, impl, iterations):
    subprocess.check_call(f"make clean", shell=True)
    binary = f"bin/crypto_kem_{scheme}_{impl}_speed.bin"
    make = f"make IMPLEMENTATION_PATH=crypto_kem/{scheme}/{impl} CRYPTO_ITERATIONS={iterations} {binary}"
    #if impl == "toom":
      #  make = f"CFLAGS=-DTOOM=1 {make}"
    subprocess.check_call(make, shell=True)    

    try:
        subprocess.check_call(f"st-flash write {binary} 0x8000000", shell=True)
        subprocess.check_call(f"st-flash reset", shell=True)
    except:
        print("flashing failed --> retry")
        return run_bench(scheme, impl, iterations)

    # get serial output and wait for '#'
    with serial.Serial(Settings.SERIAL_DEVICE, 115200, timeout=10) as dev:
        logs = []
        iteration = 0
        log = b""
        while iteration < iterations:
            device_output = dev.read()
            if device_output == b'':
                print("timeout --> retry")
                return run_bench(scheme, impl, iterations)
            sys.stdout.buffer.write(device_output)
            sys.stdout.flush()
            log += device_output
            if device_output == b'#':
                logs.append(log)
                log = b""
                iteration += 1
    return logs


def parseLogSpeed(log, ignoreErrors):
    log = log.decode(errors="ignore")
    if "error" in log.lower() and not ignoreErrors:
        raise Exception("error in scheme. this is very bad.")
    lines = str(log).splitlines()

    def get(lines, key):
        if key in lines:
            return int(lines[1+lines.index(key)])
        else:
            return None

    def cleanNullTerms(d):
        return {
            k:v
            for k, v in d.items()
            if v is not None
        }

    return cleanNullTerms({
        "ccakeygen":  get(lines, "cca keypair cycles:"),
        "encaps":  get(lines, "encaps cycles:"),
        "decaps":  get(lines, "decaps cycles:"),
        "cpakeygen" : get(lines, "cpa keypair cycles:"),
        "cpaenc" : get(lines, "cpa enc cycles:"),
        "cpadec" : get(lines, "cpa dec cycles:"),
        "matrixvector" : get(lines, "matrix vector mul cycles:"),
        "innerprod" : get(lines, "inner prod cycles:"),
        "polymul" : get(lines, "polymul cycles:"),
    })


def average(results):
    avgs = dict()
    for key in results[0].keys():
        avgs[key] = int(np.array([results[i][key] for i in range(len(results))]).mean())
    return avgs


def bench(scheme, texName, impl, iterations, outfile, ignoreErrors=False):
    logs    = run_bench(scheme, impl, iterations)
    results = []
    for log in logs:
        try:
            result = parseLogSpeed(log, ignoreErrors)
        except:
            breakpoint()
            print("parsing log failed -> retry")
            return bench(scheme, texName, impl, iterations, outfile)
        results.append(result)

    avgResults = average(results)
    print(f"% M4 results for {scheme} (impl={impl})", file=outfile)

    for key, value in avgResults.items():
        macro = toMacro(f"{texName}{key}", value)
        print(macro.strip())
        print(macro, end='', file=outfile)
    print('', file=outfile, flush=True)


with open(f"benchmarks.tex", "a") as outfile:
    iterations = 1

    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"% Benchmarking measurements written on {now}; iterations={iterations}\n", file=outfile)
    
    print(f"% Benchmarking tmvp implementations to obtain CPA cycle counts", file=outfile)    
    bench("ntruhps2048509", "ntruhpsI", "tmvp", iterations, outfile)
    bench("ntruhps2048677", "ntruhpsIII", "tmvp", iterations, outfile)
    bench("ntruhrss701", "ntruhrss", "tmvp", iterations, outfile)
    bench("ntruhps4096821", "ntruhpsV", "tmvp", iterations, outfile)
    
    print(f"% Benchmarking ntt implementations to obtain CPA cycle counts", file=outfile)    
    bench("ntruhps2048509", "ntruhpsI", "ntt", iterations, outfile)
    bench("ntruhps2048677", "ntruhpsIII", "ntt", iterations, outfile)
    bench("ntruhrss701", "ntruhrss", "ntt", iterations, outfile)
    bench("ntruhps4096821", "ntruhpsV", "ntt", iterations, outfile)

    print(f"% Benchmarking toom4 implementations to obtain CPA cycle counts", file=outfile)    
    bench("ntruhps2048509", "ntruhpsI", "toom", iterations, outfile)
    bench("ntruhps2048677", "ntruhpsIII", "toom", iterations, outfile)
    bench("ntruhrss701", "ntruhrss", "toom", iterations, outfile)
    bench("ntruhps4096821", "ntruhpsV", "toom", iterations, outfile)

    
  
