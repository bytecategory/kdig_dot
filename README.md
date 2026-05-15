<pre><code>C:\Users\usr> nslookup pornhub.com 1.1.1.1
Server:  one.one.one.one
Address:  1.1.1.1

Non-authoritative answer:
Name:    pornhub.com
Addresses:  2001::1f0d:5f23
          162.125.80.3
</code></pre>
DNS Cache Poisoning can be observed.

<pre><code>
C:\Users\usr> kdig_dot.exe @1.1.1.1 pornhub.com A +tls +tls-host=cloudflare-dns.com +ca=cacert.pem
pornhub.com.    9439    IN      A       66.254.114.41

</code>
</pre>
the problem is solved,haha.<br>
a method similar to domain fronting.
