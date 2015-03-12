# Introduction #

GCluster is a tool based on Pyew's code analysis support created to help clustering sets of executables.

# Details #

GCluster uses the graph data extracted with Pyew from a program file (PE or ELF, but the support for the last is not very good) to compare binaries. It can be used, for example, to compare 2 malwares looking different at binary level.

# Example #

Take for example the following 2 binaries:

```
e1acaf0572d7430106bd813df6640c2e  test/graphs/HGWC.ex_
73be87d0dbcc5ee9863143022ea62f51  test/graphs/BypassXtrap.ex_
```

If we compare them at binary level with a fuzzy hashing tool like SSDeep we can see they differ a lot:

```
$ ssdeep test/graphs/HGWC.ex_ test/graphs/BypassXtrap.ex_
ssdeep,1.0--blocksize:hash:hash,filename
12288:faWzgMg7v3qnCiMErQohh0F4CCJ8lnyC8rm2NY:CaHMv6CorjqnyC8rm2NY,"/home/joxean/Documentos/research/pyew/test/graphs/HGWC.ex_"
49152:C1vqjdC8rRDMIEQAePhBi70tIZDMIEQAevrv5GZS/ZoE71LGc2eC6JI/Cfnc:C1vqj9fAxYmlfACr5GZAVETeDI/Cvc,"/home/joxean/Documentos/research/pyew/test/graphs/BypassXtrap.ex_"
```

But, if we compare the files with GCluster we can see very different results:

```
$ ./gcluster.py test/graphs/HGWC.ex_ test/graphs/BypassXtrap.ex_
Expert system: Programs are 100% equals
Primes system: Programs are 100% equals
ALists system: Programs are 100% equals
```

# Algorithms #

Will be described soon :) Meanwhile, continue with the next section...

# Links #

You can read more about this tool in a post (spanish) in the [48bits blog](http://blog.48bits.com/2011/01/23/comparacion-de-binarios-por-grafo/)