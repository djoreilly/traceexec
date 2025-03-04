# Benchmarking

To get consistent results on laptops, configure any power management settings for best performance.
This fork of libmicro has fixes for Linux https://github.com/rzezeski/libMicro

## Baseline
Running `bench` several times on an unloaded system and using `multiview` to compare them shows many tests giving wildly different results across runs. But the results for the `exec` test look stable enough, so just use it.

```
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/base0.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/base1.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/base2.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/base3.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/base4.out
./multiview /tmp/base*.out > /tmp/base.html
```

<table border="1" cellspacing="1">
<tbody>
<tr>
<th>BENCHMARK</th>
<th align="right">USECS</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
</tr>
<tr>
<td>exec</td>
<td><pre>445.676000</pre></td>
<td bgcolor="#ffffff"><pre>  435.83100[   +2.3%]</pre></td>
<td bgcolor="#ffffff"><pre>  435.57800[   +2.3%]</pre></td>
<td bgcolor="#ffffff"><pre>  452.37300[   -1.5%]</pre></td>
<td bgcolor="#ffffff"><pre>  439.88400[   +1.3%]</pre></td>
</tr>
</tbody></table>

## traceexec
With traceexec running:
```
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/bpf0.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/bpf1.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/bpf2.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/bpf3.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/bpf4.out
./multiview /tmp/base0.out bpf*.out > /tmp/bpf.html
```
The overhead appears to be <10%
<table border="1" cellspacing="1">
<tbody>
<tr>
<th>BENCHMARK</th>
<th align="right">USECS</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
</tr>
<tr>
<td>exec</td>
<td><pre>445.676000</pre></td>
<td bgcolor="#ffffff"><pre>  478.28500[   -7.3%]</pre></td>
<td bgcolor="#ffffff"><pre>  483.54100[   -8.5%]</pre></td>
<td bgcolor="#ffffff"><pre>  488.79700[   -9.7%]</pre></td>
<td bgcolor="#ffffff"><pre>  478.07800[   -7.3%]</pre></td>
<td bgcolor="#ffffff"><pre>  481.30300[   -8.0%]</pre></td>
</tr>
</tbody></table>

## Audit
With the `auditd` service running and traceexec stopped:
```
auditctl -d never,task
auditctl -a always,exit -F arch=b32 -S execve -F key=bench_test
auditctl -a always,exit -F arch=b64 -S execve -F key=bench_test

bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/audit0.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/audit1.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/audit2.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/audit3.out
bin/exec -E -C 10000 -D 10 -L -S -N exec >/tmp/audit4.out
./multiview /tmp/base0.out /tmp/audit*out > /tmp/audit.html
```
The overhead appears to be almost twice that of traceexec:
<table border="1" cellspacing="1">
<tbody>
<tr>
<th>BENCHMARK</th>
<th align="right">USECS</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
<th align="right">USECS [percentage]</th>
</tr>
<tr>
<td>exec</td>
<td><pre>445.676000</pre></td>
<td bgcolor="#fffdfd"><pre>  500.61400[  -12.3%]</pre></td>
<td bgcolor="#fffdfd"><pre>  503.13400[  -12.9%]</pre></td>
<td bgcolor="#fffdfd"><pre>  503.60800[  -13.0%]</pre></td>
<td bgcolor="#fffbfb"><pre>  512.91900[  -15.1%]</pre></td>
<td bgcolor="#fffbfb"><pre>  515.29200[  -15.6%]</pre></td>
</tr>
</tbody></table>


